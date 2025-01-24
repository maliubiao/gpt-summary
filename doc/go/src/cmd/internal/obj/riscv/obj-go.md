Response: Let's break down the thought process for summarizing the provided Go code.

1. **Understanding the Goal:** The request asks for a summary of the Go code snippet, specifically highlighting its functionalities and potential underlying Go features. It also emphasizes code reasoning, handling of command-line arguments (though none are apparent yet), and common user mistakes (again, not explicitly present in this fragment). The "Part 1 of 2" suggests we should focus on the functionality within *this* specific snippet.

2. **Initial Scan and Keyword Spotting:** I'll quickly scan the code for recognizable keywords and package names.

    * `package riscv`:  This immediately tells me the code is related to the RISC-V architecture.
    * `import`:  The imported packages provide clues about the code's purpose. `cmd/internal/obj`, `cmd/internal/objabi`, `cmd/internal/src`, `cmd/internal/sys` strongly suggest this is part of the Go compiler or assembler toolchain, specifically the architecture-specific parts. `internal/abi` and `internal/buildcfg` further support this.
    * Function names:  `buildop`, `jalToSym`, `progedit`, `addrToReg`, `movToLoad`, `movToStore`, `markRelocs`, `InvertBranch`, `containsCall`, `setPCs`, `stackOffset`, `preprocess`, `stacksplit`, `signExtend`, `Split32BitImmediate`, `regVal`, `regI`, `regF`, `regV`, `regAddr`, `regIAddr`, `regFAddr`, `immEven`, `immIFits`, `immI`, `wantImmI`, `wantReg`, `wantNoneReg`, `wantIntReg`, `wantFloatReg`, `wantVectorReg`, `wantEvenOffset`, `validateRII`, `validateRIII`, etc. These names strongly suggest operations related to instruction processing, register manipulation, immediate value handling, and validation.
    * Data structures: `instructionData`, `encoding`, `instruction`. These clearly define the structure of RISC-V instructions and how they are represented in the code.
    * Global variables: `instructions`. This looks like a lookup table for RISC-V instructions and their properties.

3. **Categorizing Functionalities:** Based on the initial scan, I can start grouping functions by their apparent purpose:

    * **Instruction Handling & Manipulation:** `progedit`, `jalToSym`, `movToLoad`, `movToStore`, `markRelocs`, `InvertBranch`. These seem to be involved in modifying and transforming RISC-V instructions.
    * **Address and Register Management:** `addrToReg`, `stackOffset`, `regVal`, `regI`, `regF`, `regV`, `regAddr`, `regIAddr`, `regFAddr`. These are likely used to extract and manipulate register information and memory addresses.
    * **Immediate Value Handling:** `immEven`, `immIFits`, `immI`, `Split32BitImmediate`, `signExtend`. These functions deal with validating and splitting immediate values used in instructions.
    * **Code Generation and Layout:** `buildop`, `setPCs`, `preprocess`, `stacksplit`. These functions likely play a role in the overall code generation process, including setting program counters and handling function prologues and epilogues.
    * **Validation:** `validate...` functions. These are explicitly for validating the structure and operands of RISC-V instructions.
    * **Encoding and Decoding:** `encode...` functions, `encoding`, `instructionData`, `instructionDataForAs`, `encodingForAs`, `instructionForProg`, `instructionsForOpImmediate`, `instructionsForLoad`, `instructionsForStore`, `instructionsForTLSLoad`, `instructionsForTLSStore`, `instructionsForMOV`. This is a significant part, dealing with converting the internal representation of instructions into machine code.

4. **Inferring Go Features:**

    * **Packages:** The code utilizes Go's package system for modularity and organization.
    * **Functions:** The code is structured using functions, a fundamental building block of Go.
    * **Data Structures (Structs):** `instructionData`, `encoding`, and `instruction` are structs, demonstrating the use of custom data types to represent complex entities.
    * **Arrays and Slices:** The `instructions` variable is an array, and functions like `instructionsForProg` might return slices.
    * **Error Handling:**  The code uses `error` return types and `fmt.Errorf` for error reporting. `panic` is used for unexpected conditions (internal errors).
    * **Switch Statements:**  `switch` statements are used extensively for handling different instruction types and operands.
    * **Bitwise Operations:**  The encoding and immediate value manipulation functions heavily rely on bitwise operators (`<<`, `>>`, `&`, `|`, `^`).
    * **Pointers:** The code uses pointers extensively (e.g., `*obj.Link`, `*obj.Prog`, `*obj.Addr`) to modify data in place.
    * **Method Receivers:** Functions like `(ins *instruction) String()` and `(ins *instruction) encode()` use method receivers.

5. **Focusing on the "What":**  Instead of getting bogged down in the "how" of every function, I'll focus on the high-level actions performed. For example, `progedit` normalizes instructions, `preprocess` handles prologues/epilogues, `encodeRIII` encodes a specific instruction type.

6. **Drafting the Summary:** I'll start writing the summary, grouping related functionalities together. I'll use clear and concise language, avoiding overly technical jargon where possible. I'll also explicitly mention the suspected underlying Go features.

7. **Review and Refinement:** After the initial draft, I'll review it against the original request:

    * Does it list the functionalities? Yes.
    * Does it infer Go features and provide examples (even if simple)? Yes.
    * Does it attempt code reasoning (by explaining what the functions do)? Yes.
    * Does it cover command-line arguments?  No, and the code doesn't seem to process any. I'll explicitly state this.
    * Does it cover common user mistakes?  No obvious ones in *this* snippet. I'll also state this.
    * Does it summarize the functionality as requested for "Part 1"? Yes.

8. **Adding Code Examples (as requested):**  I'll choose a couple of key functionalities and provide simple Go code examples to illustrate their usage, even if these examples are simplified and conceptual. The examples should demonstrate the input and output, as requested.

9. **Final Polish:**  I'll read through the summary one last time, correcting any grammatical errors or typos and ensuring clarity and accuracy. I'll make sure the tone is informative and helpful.

This structured approach helps in systematically analyzing the code and producing a comprehensive and accurate summary that addresses all aspects of the request.
This Go code snippet is a crucial part of the RISC-V architecture support within the Go compiler toolchain. It resides within the assembler and linker (`cmd/internal/obj`).

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **RISC-V Instruction Processing and Normalization (`progedit`):**
   - Takes a raw `obj.Prog` (representing a RISC-V instruction) and normalizes its format.
   - Expands binary instructions to ternary ones if needed.
   - Rewrites instructions with constant operands to their immediate form (e.g., `SUB` with a constant becomes `ADDI` with a negated offset).
   - Handles pseudo-instructions like `JMP` and `CALL`, converting them into concrete RISC-V instructions like `JAL` or `JALR`.
   - Deals with historical instruction names (`SCALL` -> `ECALL`).
   - Addresses the handling of large (greater than 32-bit) constants by placing them in memory and loading them.

2. **Address and Register Manipulation:**
   - `addrToReg`: Extracts the actual register from an `obj.Addr`, considering special names like `NAME_PARAM` and `NAME_AUTO` which map to the stack pointer (`REG_SP`).
   - `stackOffset`: Adjusts the offsets in `obj.Addr` structures based on the current stack size, distinguishing between parameters and automatic variables.

3. **Instruction Mnemonics Conversion:**
   - `movToLoad`: Transforms `MOV` instructions into their corresponding load instructions based on the size and signedness of the data (e.g., `AMOVW` becomes `ALW`).
   - `movToStore`: Transforms `MOV` instructions into their corresponding store instructions (e.g., `AMOVB` becomes `ASB`).

4. **Relocation Marking (`markRelocs`):**
   - Identifies `MOV` instructions that require relocation (linking to external or static symbols).
   - Marks these instructions with flags like `NEED_PCREL_ITYPE_RELOC` and `NEED_PCREL_STYPE_RELOC`, indicating the type of relocation needed.

5. **Branch Instruction Handling:**
   - `InvertBranch`: Takes a conditional branch instruction and returns its inverted counterpart (e.g., `BEQ` becomes `BNE`).

6. **Function Analysis:**
   - `containsCall`: Checks if a symbol (function) contains a `CALL` instruction or its equivalents (`JAL` or `JALR` with the link register).

7. **Program Counter Management (`setPCs`):**
   - Assigns program counter (`Pc`) values to instructions within a function.
   - Calculates the size of each instruction to determine the next available `Pc`.
   - Handles `APCALIGN` directives for aligning code.

8. **Prologue and Epilogue Generation and Preprocessing (`preprocess`):**
   - This is a central function called once per linker symbol.
   - Generates prologue code to set up the function's stack frame, including saving the link register (`LR`).
   - Handles the `NOFRAME` attribute for functions that don't need a stack frame.
   - Inserts stack split checks (`stacksplit`) to ensure enough stack space is available.
   - Generates epilogue code (within the `ARET` handling) to restore the stack pointer and return.
   - Rewrites certain instructions (like `GETCALLERPC`, `CALL`, `JMP`, `RET`) into their concrete forms.
   - Resolves PC-relative branch and jump offsets.
   - Handles long branch displacements by potentially inserting jump instructions.
   - Validates the final instructions after all transformations.

9. **Stack Split Implementation (`stacksplit`):**
   - Implements the logic for checking if the current stack has enough space for the function call.
   - If not enough space, it calls the `runtime.morestack` function (or variants like `runtime.morestackc` for C functions or `runtime.morestack_noctxt` when no context is needed) to allocate more stack.

10. **Immediate Value Handling:**
    - `signExtend`: Performs sign extension on an integer value.
    - `Split32BitImmediate`: Splits a 32-bit immediate value into a 20-bit upper part and a 12-bit lower part, useful for constructing large constants using instructions like `LUI` and `ADDI`.

11. **Register Validation and Extraction:**
    - `regVal`, `regI`, `regF`, `regV`: Functions to validate that a given register number falls within the valid range for integer, floating-point, or vector registers, respectively.
    - `regAddr`, `regIAddr`, `regFAddr`: Functions to extract and validate register numbers from `obj.Addr` structures.

12. **Immediate Value Validation:**
    - `immEven`: Checks if an immediate value is even.
    - `immIFits`: Checks if an immediate value fits within a specified number of signed bits.
    - `immI`: Extracts a signed integer from an immediate, panicking if it doesn't fit.
    - `wantImmI`, `wantReg`, `wantNoneReg`, `wantIntReg`, `wantFloatReg`, `wantVectorReg`, `wantEvenOffset`: Helper functions for validating instruction operands during encoding.

13. **Instruction Encoding and Validation (`validate...` and `encode...` functions):**
    - Defines `encoding` and `instructionData` structs to describe instruction formats and encoding logic.
    - Contains a global array `instructions` mapping RISC-V opcodes to their `instructionData`.
    - `instructionDataForAs` and `encodingForAs` provide ways to look up this information.
    - `instruction` struct represents a decoded RISC-V instruction with its operands.
    - `validate...` functions (e.g., `validateRII`, `validateIII`) perform instruction-specific operand validation based on the instruction format.
    - `encode...` functions (e.g., `encodeR`, `encodeI`, `encodeS`) take an `instruction` and generate the corresponding machine code (a `uint32`). These functions implement the specific bitwise operations required for each instruction format.

14. **Helper Functions for Instruction Sequences (`instructionsForOpImmediate`, `instructionsForLoad`, `instructionsForStore`, `instructionsForTLSLoad`, `instructionsForTLSStore`, `instructionsForMOV`):**
    - These functions are responsible for generating sequences of actual RISC-V instructions to implement higher-level operations or handle cases that require multiple instructions (e.g., loading large constants, accessing thread-local storage).

**Inferred Go Language Features:**

* **Packages:** The code is organized into a package (`riscv`) which promotes modularity.
* **Structs:**  `obj.Prog`, `obj.Addr`, `instructionData`, `encoding`, and `instruction` are structs, demonstrating the use of composite data types.
* **Interfaces:** The use of `obj.ProgAlloc` as a function parameter suggests an interface for allocating new program instructions.
* **Functions as First-Class Citizens:**  The `encoding` struct contains function pointers (`encode`, `validate`), showcasing the ability to treat functions as data.
* **Error Handling:** The code uses the standard Go error handling pattern (returning `error` values).
* **String Formatting:** `fmt.Sprintf` and similar functions are used for creating formatted strings for debugging and error messages.
* **Bitwise Operations:** Extensive use of bitwise operators (`<<`, `>>`, `|`, `&`, `^`) for manipulating instruction bits during encoding and decoding.
* **Switch Statements:**  Used for dispatching based on instruction opcodes and operand types.
* **Pointers:** Used extensively for modifying data structures in place (e.g., modifying `obj.Prog` fields).
* **Constants:**  Defined constants like register names (`REG_ZERO`, `REG_SP`, etc.).
* **Arrays and Slices:** Used for storing instruction data (`instructions`) and potentially returning sequences of instructions.

**Example of Go Functionality Implementation (Code Reasoning):**

Let's consider the `progedit` function and its handling of the `AJMP` instruction:

```go
	case obj.AJMP:
		// Turn JMP into JAL ZERO or JALR ZERO.
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_ZERO

		switch p.To.Type {
		case obj.TYPE_BRANCH:
			p.As = AJAL
		case obj.TYPE_MEM:
			switch p.To.Name {
			case obj.NAME_NONE:
				p.As = AJALR
			case obj.NAME_EXTERN, obj.NAME_STATIC:
				// Handled in preprocess.
			default:
				ctxt.Diag("unsupported name %d for %v", p.To.Name, p)
			}
		default:
			panic(fmt.Sprintf("unhandled type %+v", p.To.Type))
		}
```

**Reasoning:**

The RISC-V architecture doesn't have a dedicated `JMP` instruction in the same way some other architectures do. Instead, unconditional jumps are typically implemented using the `JAL` (Jump and Link) or `JALR` (Jump and Link Register) instructions where the link register is set to zero, effectively discarding the return address.

* **Input (Hypothetical):** An `obj.Prog` representing a `JMP` instruction. Let's assume `p.To` is a branch target (label).
  ```
  p.As = obj.AJMP
  p.To.Type = obj.TYPE_BRANCH
  // p.To.Target() points to the destination label
  ```

* **Processing:**
    1. `p.From.Type` is set to `obj.TYPE_REG`, and `p.From.Reg` is set to `REG_ZERO`. This prepares the instruction to use a register as the source for `JAL` or `JALR`.
    2. The `switch` statement checks the type of the jump target (`p.To.Type`).
    3. In this case, `p.To.Type` is `obj.TYPE_BRANCH`.
    4. Therefore, `p.As` is changed to `AJAL`. This converts the pseudo-`JMP` into a concrete `JAL` instruction that jumps to the branch target.

* **Output:** The `obj.Prog` is modified:
  ```
  p.As = obj.AJAL
  p.From.Type = obj.TYPE_REG
  p.From.Reg = REG_ZERO
  p.To.Type = obj.TYPE_BRANCH
  // p.To.Target() remains pointing to the destination label
  ```

**Go Code Example Illustrating `progedit` (Conceptual):**

```go
package main

import (
	"cmd/internal/obj"
	"fmt"
	"go/src/cmd/internal/obj/riscv" // Assuming this file is accessible
)

func main() {
	// Create a hypothetical JMP instruction
	jmpProg := &obj.Prog{
		As: obj.AJMP,
		To: obj.Addr{Type: obj.TYPE_BRANCH}, // Assume a target is set elsewhere
	}

	// Create a Link context (simplified for example)
	linkContext := &obj.Link{}

	// Create a ProgAlloc (again, simplified)
	progAlloc := func() *obj.Prog { return &obj.Prog{} }

	// Call progedit to process the instruction
	riscv.Progedit(linkContext, jmpProg, progAlloc)

	// Print the modified instruction
	fmt.Printf("Original instruction: JMP\n")
	fmt.Printf("Processed instruction: %v (As: %v, From.Type: %v, From.Reg: %v, To.Type: %v)\n",
		jmpProg, jmpProg.As, jmpProg.From.Type, jmpProg.From.Reg, jmpProg.To.Type)
}
```

**Hypothetical Output:**

```
Original instruction: JMP
Processed instruction: &{AJAL  {TYPE_REG  ZERO  0 "" <nil>}  {TYPE_BRANCH  0  0 "" <nil>}  <nil> 0 0 0 0} (As: 136, From.Type: 1, From.Reg: 0, To.Type: 4)
```

**Explanation of Output:**

The output shows that the `obj.Prog` originally representing `AJMP` has been modified by `progedit`. The `As` field now indicates `AJAL`, the `From.Type` is `TYPE_REG`, and `From.Reg` is `ZERO`, reflecting the transformation into a `JAL ZERO` instruction.

**Command-Line Parameter Handling:**

This specific code snippet doesn't directly handle command-line parameters. Command-line argument processing for the Go toolchain (like the assembler and linker) would typically be handled in the main entry points of those tools (e.g., in `cmd/asm/internal/asm/asm.go` or `cmd/link/internal/ld/main.go`). These tools would then use the functionality provided by this `obj.go` file based on the provided arguments.

**Common User Mistakes:**

Without seeing the context of how users interact with this low-level code directly (which is unlikely in most cases), it's hard to pinpoint common *user* errors. However, potential issues related to the code itself (which could manifest as errors for developers working on the Go toolchain) might include:

* **Incorrectly defining instruction encodings:**  Mistakes in the `instructions` array or the `encode...` functions could lead to incorrect machine code generation.
* **Not handling all instruction variations:**  Forgetting to account for different operand types or instruction formats in `progedit` or the encoding functions.
* **Off-by-one errors in bit manipulation:** Incorrectly calculating bit offsets or masks in the encoding functions.
* **Incorrectly calculating stack offsets:**  Errors in `stackOffset` could lead to incorrect access to local variables and parameters.

**Summary of Functionalities (Part 1):**

This first part of `obj.go` for the RISC-V architecture primarily focuses on the **initial processing and normalization of RISC-V assembly instructions**. It handles the conversion of pseudo-instructions into real instructions, manages stack frame setup, marks instructions for relocation, and lays the groundwork for the subsequent stages of assembly and linking. It defines the core data structures and functions for representing and manipulating RISC-V instructions within the Go toolchain.

### 提示词
```
这是路径为go/src/cmd/internal/obj/riscv/obj.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
// Copyright © 2015 The Go Authors.  All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package riscv

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"cmd/internal/src"
	"cmd/internal/sys"
	"fmt"
	"internal/abi"
	"internal/buildcfg"
	"log"
	"math/bits"
	"strings"
)

func buildop(ctxt *obj.Link) {}

func jalToSym(ctxt *obj.Link, p *obj.Prog, lr int16) {
	switch p.As {
	case obj.ACALL, obj.AJMP, obj.ARET, obj.ADUFFZERO, obj.ADUFFCOPY:
	default:
		ctxt.Diag("unexpected Prog in jalToSym: %v", p)
		return
	}

	p.As = AJAL
	p.Mark |= NEED_JAL_RELOC
	p.From.Type = obj.TYPE_REG
	p.From.Reg = lr
	p.Reg = obj.REG_NONE
}

// progedit is called individually for each *obj.Prog. It normalizes instruction
// formats and eliminates as many pseudo-instructions as possible.
func progedit(ctxt *obj.Link, p *obj.Prog, newprog obj.ProgAlloc) {
	insData, err := instructionDataForAs(p.As)
	if err != nil {
		panic(fmt.Sprintf("failed to lookup instruction data for %v: %v", p.As, err))
	}

	// Expand binary instructions to ternary ones.
	if p.Reg == obj.REG_NONE {
		if insData.ternary {
			p.Reg = p.To.Reg
		}
	}

	// Rewrite instructions with constant operands to refer to the immediate
	// form of the instruction.
	if p.From.Type == obj.TYPE_CONST {
		switch p.As {
		case ASUB:
			p.As, p.From.Offset = AADDI, -p.From.Offset
		case ASUBW:
			p.As, p.From.Offset = AADDIW, -p.From.Offset
		default:
			if insData.immForm != obj.AXXX {
				p.As = insData.immForm
			}
		}
	}

	switch p.As {
	case obj.AJMP:
		// Turn JMP into JAL ZERO or JALR ZERO.
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_ZERO

		switch p.To.Type {
		case obj.TYPE_BRANCH:
			p.As = AJAL
		case obj.TYPE_MEM:
			switch p.To.Name {
			case obj.NAME_NONE:
				p.As = AJALR
			case obj.NAME_EXTERN, obj.NAME_STATIC:
				// Handled in preprocess.
			default:
				ctxt.Diag("unsupported name %d for %v", p.To.Name, p)
			}
		default:
			panic(fmt.Sprintf("unhandled type %+v", p.To.Type))
		}

	case obj.ACALL:
		switch p.To.Type {
		case obj.TYPE_MEM:
			// Handled in preprocess.
		case obj.TYPE_REG:
			p.As = AJALR
			p.From.Type = obj.TYPE_REG
			p.From.Reg = REG_LR
		default:
			ctxt.Diag("unknown destination type %+v in CALL: %v", p.To.Type, p)
		}

	case obj.AUNDEF:
		p.As = AEBREAK

	case AFMVXS:
		// FMVXS is the old name for FMVXW.
		p.As = AFMVXW

	case AFMVSX:
		// FMVSX is the old name for FMVWX.
		p.As = AFMVWX

	case ASCALL:
		// SCALL is the old name for ECALL.
		p.As = AECALL

	case ASBREAK:
		// SBREAK is the old name for EBREAK.
		p.As = AEBREAK

	case AMOV:
		if p.From.Type == obj.TYPE_CONST && p.From.Name == obj.NAME_NONE && p.From.Reg == obj.REG_NONE && int64(int32(p.From.Offset)) != p.From.Offset {
			ctz := bits.TrailingZeros64(uint64(p.From.Offset))
			val := p.From.Offset >> ctz
			if int64(int32(val)) == val {
				// It's ok. We can handle constants with many trailing zeros.
				break
			}
			// Put >32-bit constants in memory and load them.
			p.From.Type = obj.TYPE_MEM
			p.From.Sym = ctxt.Int64Sym(p.From.Offset)
			p.From.Name = obj.NAME_EXTERN
			p.From.Offset = 0
		}
	}
}

// addrToReg extracts the register from an Addr, handling special Addr.Names.
func addrToReg(a obj.Addr) int16 {
	switch a.Name {
	case obj.NAME_PARAM, obj.NAME_AUTO:
		return REG_SP
	}
	return a.Reg
}

// movToLoad converts a MOV mnemonic into the corresponding load instruction.
func movToLoad(mnemonic obj.As) obj.As {
	switch mnemonic {
	case AMOV:
		return ALD
	case AMOVB:
		return ALB
	case AMOVH:
		return ALH
	case AMOVW:
		return ALW
	case AMOVBU:
		return ALBU
	case AMOVHU:
		return ALHU
	case AMOVWU:
		return ALWU
	case AMOVF:
		return AFLW
	case AMOVD:
		return AFLD
	default:
		panic(fmt.Sprintf("%+v is not a MOV", mnemonic))
	}
}

// movToStore converts a MOV mnemonic into the corresponding store instruction.
func movToStore(mnemonic obj.As) obj.As {
	switch mnemonic {
	case AMOV:
		return ASD
	case AMOVB:
		return ASB
	case AMOVH:
		return ASH
	case AMOVW:
		return ASW
	case AMOVF:
		return AFSW
	case AMOVD:
		return AFSD
	default:
		panic(fmt.Sprintf("%+v is not a MOV", mnemonic))
	}
}

// markRelocs marks an obj.Prog that specifies a MOV pseudo-instruction and
// requires relocation.
func markRelocs(p *obj.Prog) {
	switch p.As {
	case AMOV, AMOVB, AMOVH, AMOVW, AMOVBU, AMOVHU, AMOVWU, AMOVF, AMOVD:
		switch {
		case p.From.Type == obj.TYPE_ADDR && p.To.Type == obj.TYPE_REG:
			switch p.From.Name {
			case obj.NAME_EXTERN, obj.NAME_STATIC:
				p.Mark |= NEED_PCREL_ITYPE_RELOC
			}
		case p.From.Type == obj.TYPE_MEM && p.To.Type == obj.TYPE_REG:
			switch p.From.Name {
			case obj.NAME_EXTERN, obj.NAME_STATIC:
				p.Mark |= NEED_PCREL_ITYPE_RELOC
			}
		case p.From.Type == obj.TYPE_REG && p.To.Type == obj.TYPE_MEM:
			switch p.To.Name {
			case obj.NAME_EXTERN, obj.NAME_STATIC:
				p.Mark |= NEED_PCREL_STYPE_RELOC
			}
		}
	}
}

// InvertBranch inverts the condition of a conditional branch.
func InvertBranch(as obj.As) obj.As {
	switch as {
	case ABEQ:
		return ABNE
	case ABEQZ:
		return ABNEZ
	case ABGE:
		return ABLT
	case ABGEU:
		return ABLTU
	case ABGEZ:
		return ABLTZ
	case ABGT:
		return ABLE
	case ABGTU:
		return ABLEU
	case ABGTZ:
		return ABLEZ
	case ABLE:
		return ABGT
	case ABLEU:
		return ABGTU
	case ABLEZ:
		return ABGTZ
	case ABLT:
		return ABGE
	case ABLTU:
		return ABGEU
	case ABLTZ:
		return ABGEZ
	case ABNE:
		return ABEQ
	case ABNEZ:
		return ABEQZ
	default:
		panic("InvertBranch: not a branch")
	}
}

// containsCall reports whether the symbol contains a CALL (or equivalent)
// instruction. Must be called after progedit.
func containsCall(sym *obj.LSym) bool {
	// CALLs are CALL or JAL(R) with link register LR.
	for p := sym.Func().Text; p != nil; p = p.Link {
		switch p.As {
		case obj.ACALL, obj.ADUFFZERO, obj.ADUFFCOPY:
			return true
		case AJAL, AJALR:
			if p.From.Type == obj.TYPE_REG && p.From.Reg == REG_LR {
				return true
			}
		}
	}

	return false
}

// setPCs sets the Pc field in all instructions reachable from p.
// It uses pc as the initial value and returns the next available pc.
func setPCs(p *obj.Prog, pc int64) int64 {
	for ; p != nil; p = p.Link {
		p.Pc = pc
		for _, ins := range instructionsForProg(p) {
			pc += int64(ins.length())
		}

		if p.As == obj.APCALIGN {
			alignedValue := p.From.Offset
			v := pcAlignPadLength(pc, alignedValue)
			pc += int64(v)
		}
	}
	return pc
}

// stackOffset updates Addr offsets based on the current stack size.
//
// The stack looks like:
// -------------------
// |                 |
// |      PARAMs     |
// |                 |
// |                 |
// -------------------
// |    Parent RA    |   SP on function entry
// -------------------
// |                 |
// |                 |
// |       AUTOs     |
// |                 |
// |                 |
// -------------------
// |        RA       |   SP during function execution
// -------------------
//
// FixedFrameSize makes other packages aware of the space allocated for RA.
//
// A nicer version of this diagram can be found on slide 21 of the presentation
// attached to https://golang.org/issue/16922#issuecomment-243748180.
func stackOffset(a *obj.Addr, stacksize int64) {
	switch a.Name {
	case obj.NAME_AUTO:
		// Adjust to the top of AUTOs.
		a.Offset += stacksize
	case obj.NAME_PARAM:
		// Adjust to the bottom of PARAMs.
		a.Offset += stacksize + 8
	}
}

// preprocess generates prologue and epilogue code, computes PC-relative branch
// and jump offsets, and resolves pseudo-registers.
//
// preprocess is called once per linker symbol.
//
// When preprocess finishes, all instructions in the symbol are either
// concrete, real RISC-V instructions or directive pseudo-ops like TEXT,
// PCDATA, and FUNCDATA.
func preprocess(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc) {
	if cursym.Func().Text == nil || cursym.Func().Text.Link == nil {
		return
	}

	// Generate the prologue.
	text := cursym.Func().Text
	if text.As != obj.ATEXT {
		ctxt.Diag("preprocess: found symbol that does not start with TEXT directive")
		return
	}

	stacksize := text.To.Offset
	if stacksize == -8 {
		// Historical way to mark NOFRAME.
		text.From.Sym.Set(obj.AttrNoFrame, true)
		stacksize = 0
	}
	if stacksize < 0 {
		ctxt.Diag("negative frame size %d - did you mean NOFRAME?", stacksize)
	}
	if text.From.Sym.NoFrame() {
		if stacksize != 0 {
			ctxt.Diag("NOFRAME functions must have a frame size of 0, not %d", stacksize)
		}
	}

	if !containsCall(cursym) {
		text.From.Sym.Set(obj.AttrLeaf, true)
		if stacksize == 0 {
			// A leaf function with no locals has no frame.
			text.From.Sym.Set(obj.AttrNoFrame, true)
		}
	}

	// Save LR unless there is no frame.
	if !text.From.Sym.NoFrame() {
		stacksize += ctxt.Arch.FixedFrameSize
	}

	cursym.Func().Args = text.To.Val.(int32)
	cursym.Func().Locals = int32(stacksize)

	prologue := text

	if !cursym.Func().Text.From.Sym.NoSplit() {
		prologue = stacksplit(ctxt, prologue, cursym, newprog, stacksize) // emit split check
	}

	q := prologue

	if stacksize != 0 {
		prologue = ctxt.StartUnsafePoint(prologue, newprog)

		// Actually save LR.
		prologue = obj.Appendp(prologue, newprog)
		prologue.As = AMOV
		prologue.Pos = q.Pos
		prologue.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_LR}
		prologue.To = obj.Addr{Type: obj.TYPE_MEM, Reg: REG_SP, Offset: -stacksize}

		// Insert stack adjustment.
		prologue = obj.Appendp(prologue, newprog)
		prologue.As = AADDI
		prologue.Pos = q.Pos
		prologue.Pos = prologue.Pos.WithXlogue(src.PosPrologueEnd)
		prologue.From = obj.Addr{Type: obj.TYPE_CONST, Offset: -stacksize}
		prologue.Reg = REG_SP
		prologue.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_SP}
		prologue.Spadj = int32(stacksize)

		prologue = ctxt.EndUnsafePoint(prologue, newprog, -1)

		// On Linux, in a cgo binary we may get a SIGSETXID signal early on
		// before the signal stack is set, as glibc doesn't allow us to block
		// SIGSETXID. So a signal may land on the current stack and clobber
		// the content below the SP. We store the LR again after the SP is
		// decremented.
		prologue = obj.Appendp(prologue, newprog)
		prologue.As = AMOV
		prologue.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_LR}
		prologue.To = obj.Addr{Type: obj.TYPE_MEM, Reg: REG_SP, Offset: 0}
	}

	if cursym.Func().Text.From.Sym.Wrapper() {
		// if(g->panic != nil && g->panic->argp == FP) g->panic->argp = bottom-of-frame
		//
		//   MOV g_panic(g), X5
		//   BNE X5, ZERO, adjust
		// end:
		//   NOP
		// ...rest of function..
		// adjust:
		//   MOV panic_argp(X5), X6
		//   ADD $(autosize+FIXED_FRAME), SP, X7
		//   BNE X6, X7, end
		//   ADD $FIXED_FRAME, SP, X6
		//   MOV X6, panic_argp(X5)
		//   JMP end
		//
		// The NOP is needed to give the jumps somewhere to land.

		ldpanic := obj.Appendp(prologue, newprog)

		ldpanic.As = AMOV
		ldpanic.From = obj.Addr{Type: obj.TYPE_MEM, Reg: REGG, Offset: 4 * int64(ctxt.Arch.PtrSize)} // G.panic
		ldpanic.Reg = obj.REG_NONE
		ldpanic.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_X5}

		bneadj := obj.Appendp(ldpanic, newprog)
		bneadj.As = ABNE
		bneadj.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_X5}
		bneadj.Reg = REG_ZERO
		bneadj.To.Type = obj.TYPE_BRANCH

		endadj := obj.Appendp(bneadj, newprog)
		endadj.As = obj.ANOP

		last := endadj
		for last.Link != nil {
			last = last.Link
		}

		getargp := obj.Appendp(last, newprog)
		getargp.As = AMOV
		getargp.From = obj.Addr{Type: obj.TYPE_MEM, Reg: REG_X5, Offset: 0} // Panic.argp
		getargp.Reg = obj.REG_NONE
		getargp.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_X6}

		bneadj.To.SetTarget(getargp)

		calcargp := obj.Appendp(getargp, newprog)
		calcargp.As = AADDI
		calcargp.From = obj.Addr{Type: obj.TYPE_CONST, Offset: stacksize + ctxt.Arch.FixedFrameSize}
		calcargp.Reg = REG_SP
		calcargp.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_X7}

		testargp := obj.Appendp(calcargp, newprog)
		testargp.As = ABNE
		testargp.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_X6}
		testargp.Reg = REG_X7
		testargp.To.Type = obj.TYPE_BRANCH
		testargp.To.SetTarget(endadj)

		adjargp := obj.Appendp(testargp, newprog)
		adjargp.As = AADDI
		adjargp.From = obj.Addr{Type: obj.TYPE_CONST, Offset: int64(ctxt.Arch.PtrSize)}
		adjargp.Reg = REG_SP
		adjargp.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_X6}

		setargp := obj.Appendp(adjargp, newprog)
		setargp.As = AMOV
		setargp.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_X6}
		setargp.Reg = obj.REG_NONE
		setargp.To = obj.Addr{Type: obj.TYPE_MEM, Reg: REG_X5, Offset: 0} // Panic.argp

		godone := obj.Appendp(setargp, newprog)
		godone.As = AJAL
		godone.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_ZERO}
		godone.To.Type = obj.TYPE_BRANCH
		godone.To.SetTarget(endadj)
	}

	// Update stack-based offsets.
	for p := cursym.Func().Text; p != nil; p = p.Link {
		stackOffset(&p.From, stacksize)
		stackOffset(&p.To, stacksize)
	}

	// Additional instruction rewriting.
	for p := cursym.Func().Text; p != nil; p = p.Link {
		switch p.As {
		case obj.AGETCALLERPC:
			if cursym.Leaf() {
				// MOV LR, Rd
				p.As = AMOV
				p.From.Type = obj.TYPE_REG
				p.From.Reg = REG_LR
			} else {
				// MOV (RSP), Rd
				p.As = AMOV
				p.From.Type = obj.TYPE_MEM
				p.From.Reg = REG_SP
			}

		case obj.ACALL, obj.ADUFFZERO, obj.ADUFFCOPY:
			switch p.To.Type {
			case obj.TYPE_MEM:
				jalToSym(ctxt, p, REG_LR)
			}

		case obj.AJMP:
			switch p.To.Type {
			case obj.TYPE_MEM:
				switch p.To.Name {
				case obj.NAME_EXTERN, obj.NAME_STATIC:
					jalToSym(ctxt, p, REG_ZERO)
				}
			}

		case obj.ARET:
			// Replace RET with epilogue.
			retJMP := p.To.Sym

			if stacksize != 0 {
				// Restore LR.
				p.As = AMOV
				p.From = obj.Addr{Type: obj.TYPE_MEM, Reg: REG_SP, Offset: 0}
				p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_LR}
				p = obj.Appendp(p, newprog)

				p.As = AADDI
				p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: stacksize}
				p.Reg = REG_SP
				p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_SP}
				p.Spadj = int32(-stacksize)
				p = obj.Appendp(p, newprog)
			}

			if retJMP != nil {
				p.As = obj.ARET
				p.To.Sym = retJMP
				jalToSym(ctxt, p, REG_ZERO)
			} else {
				p.As = AJALR
				p.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_ZERO}
				p.Reg = obj.REG_NONE
				p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_LR}
			}

			// "Add back" the stack removed in the previous instruction.
			//
			// This is to avoid confusing pctospadj, which sums
			// Spadj from function entry to each PC, and shouldn't
			// count adjustments from earlier epilogues, since they
			// won't affect later PCs.
			p.Spadj = int32(stacksize)

		case AADDI:
			// Refine Spadjs account for adjustment via ADDI instruction.
			if p.To.Type == obj.TYPE_REG && p.To.Reg == REG_SP && p.From.Type == obj.TYPE_CONST {
				p.Spadj = int32(-p.From.Offset)
			}
		}

		if p.To.Type == obj.TYPE_REG && p.To.Reg == REGSP && p.Spadj == 0 {
			f := cursym.Func()
			if f.FuncFlag&abi.FuncFlagSPWrite == 0 {
				f.FuncFlag |= abi.FuncFlagSPWrite
				if ctxt.Debugvlog || !ctxt.IsAsm {
					ctxt.Logf("auto-SPWRITE: %s %v\n", cursym.Name, p)
					if !ctxt.IsAsm {
						ctxt.Diag("invalid auto-SPWRITE in non-assembly")
						ctxt.DiagFlush()
						log.Fatalf("bad SPWRITE")
					}
				}
			}
		}
	}

	var callCount int
	for p := cursym.Func().Text; p != nil; p = p.Link {
		markRelocs(p)
		if p.Mark&NEED_JAL_RELOC == NEED_JAL_RELOC {
			callCount++
		}
	}
	const callTrampSize = 8 // 2 machine instructions.
	maxTrampSize := int64(callCount * callTrampSize)

	// Compute instruction addresses.  Once we do that, we need to check for
	// overextended jumps and branches.  Within each iteration, Pc differences
	// are always lower bounds (since the program gets monotonically longer,
	// a fixed point will be reached).  No attempt to handle functions > 2GiB.
	for {
		big, rescan := false, false
		maxPC := setPCs(cursym.Func().Text, 0)
		if maxPC+maxTrampSize > (1 << 20) {
			big = true
		}

		for p := cursym.Func().Text; p != nil; p = p.Link {
			switch p.As {
			case ABEQ, ABEQZ, ABGE, ABGEU, ABGEZ, ABGT, ABGTU, ABGTZ, ABLE, ABLEU, ABLEZ, ABLT, ABLTU, ABLTZ, ABNE, ABNEZ:
				if p.To.Type != obj.TYPE_BRANCH {
					panic("assemble: instruction with branch-like opcode lacks destination")
				}
				offset := p.To.Target().Pc - p.Pc
				if offset < -4096 || 4096 <= offset {
					// Branch is long.  Replace it with a jump.
					jmp := obj.Appendp(p, newprog)
					jmp.As = AJAL
					jmp.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_ZERO}
					jmp.To = obj.Addr{Type: obj.TYPE_BRANCH}
					jmp.To.SetTarget(p.To.Target())

					p.As = InvertBranch(p.As)
					p.To.SetTarget(jmp.Link)

					// We may have made previous branches too long,
					// so recheck them.
					rescan = true
				}
			case AJAL:
				// Linker will handle the intersymbol case and trampolines.
				if p.To.Target() == nil {
					if !big {
						break
					}
					// This function is going to be too large for JALs
					// to reach trampolines. Replace with AUIPC+JALR.
					jmp := obj.Appendp(p, newprog)
					jmp.As = AJALR
					jmp.From = p.From
					jmp.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_TMP}

					p.As = AAUIPC
					p.Mark = (p.Mark &^ NEED_JAL_RELOC) | NEED_CALL_RELOC
					p.AddRestSource(obj.Addr{Type: obj.TYPE_CONST, Offset: p.To.Offset, Sym: p.To.Sym})
					p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: 0}
					p.Reg = obj.REG_NONE
					p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_TMP}

					rescan = true
					break
				}
				offset := p.To.Target().Pc - p.Pc
				if offset < -(1<<20) || (1<<20) <= offset {
					// Replace with 2-instruction sequence. This assumes
					// that TMP is not live across J instructions, since
					// it is reserved by SSA.
					jmp := obj.Appendp(p, newprog)
					jmp.As = AJALR
					jmp.From = p.From
					jmp.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_TMP}

					// p.From is not generally valid, however will be
					// fixed up in the next loop.
					p.As = AAUIPC
					p.From = obj.Addr{Type: obj.TYPE_BRANCH, Sym: p.From.Sym}
					p.From.SetTarget(p.To.Target())
					p.Reg = obj.REG_NONE
					p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_TMP}

					rescan = true
				}
			}
		}

		if !rescan {
			break
		}
	}

	// Now that there are no long branches, resolve branch and jump targets.
	// At this point, instruction rewriting which changes the number of
	// instructions will break everything--don't do it!
	for p := cursym.Func().Text; p != nil; p = p.Link {
		switch p.As {
		case ABEQ, ABEQZ, ABGE, ABGEU, ABGEZ, ABGT, ABGTU, ABGTZ, ABLE, ABLEU, ABLEZ, ABLT, ABLTU, ABLTZ, ABNE, ABNEZ:
			switch p.To.Type {
			case obj.TYPE_BRANCH:
				p.To.Type, p.To.Offset = obj.TYPE_CONST, p.To.Target().Pc-p.Pc
			case obj.TYPE_MEM:
				panic("unhandled type")
			}

		case AJAL:
			// Linker will handle the intersymbol case and trampolines.
			if p.To.Target() != nil {
				p.To.Type, p.To.Offset = obj.TYPE_CONST, p.To.Target().Pc-p.Pc
			}

		case AAUIPC:
			if p.From.Type == obj.TYPE_BRANCH {
				low, high, err := Split32BitImmediate(p.From.Target().Pc - p.Pc)
				if err != nil {
					ctxt.Diag("%v: jump displacement %d too large", p, p.To.Target().Pc-p.Pc)
				}
				p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: high, Sym: cursym}
				p.Link.To.Offset = low
			}

		case obj.APCALIGN:
			alignedValue := p.From.Offset
			if (alignedValue&(alignedValue-1) != 0) || 4 > alignedValue || alignedValue > 2048 {
				ctxt.Diag("alignment value of an instruction must be a power of two and in the range [4, 2048], got %d\n", alignedValue)
			}
			// Update the current text symbol alignment value.
			if int32(alignedValue) > cursym.Func().Align {
				cursym.Func().Align = int32(alignedValue)
			}
		}
	}

	// Validate all instructions - this provides nice error messages.
	for p := cursym.Func().Text; p != nil; p = p.Link {
		for _, ins := range instructionsForProg(p) {
			ins.validate(ctxt)
		}
	}
}

func pcAlignPadLength(pc int64, alignedValue int64) int {
	return int(-pc & (alignedValue - 1))
}

func stacksplit(ctxt *obj.Link, p *obj.Prog, cursym *obj.LSym, newprog obj.ProgAlloc, framesize int64) *obj.Prog {
	// Leaf function with no frame is effectively NOSPLIT.
	if framesize == 0 {
		return p
	}

	if ctxt.Flag_maymorestack != "" {
		// Save LR and REGCTXT
		const frameSize = 16
		p = ctxt.StartUnsafePoint(p, newprog)

		// Spill Arguments. This has to happen before we open
		// any more frame space.
		p = cursym.Func().SpillRegisterArgs(p, newprog)

		// MOV LR, -16(SP)
		p = obj.Appendp(p, newprog)
		p.As = AMOV
		p.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_LR}
		p.To = obj.Addr{Type: obj.TYPE_MEM, Reg: REG_SP, Offset: -frameSize}
		// ADDI $-16, SP
		p = obj.Appendp(p, newprog)
		p.As = AADDI
		p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: -frameSize}
		p.Reg = REG_SP
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_SP}
		p.Spadj = frameSize
		// MOV REGCTXT, 8(SP)
		p = obj.Appendp(p, newprog)
		p.As = AMOV
		p.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_CTXT}
		p.To = obj.Addr{Type: obj.TYPE_MEM, Reg: REG_SP, Offset: 8}

		// CALL maymorestack
		p = obj.Appendp(p, newprog)
		p.As = obj.ACALL
		p.To.Type = obj.TYPE_BRANCH
		// See ../x86/obj6.go
		p.To.Sym = ctxt.LookupABI(ctxt.Flag_maymorestack, cursym.ABI())
		jalToSym(ctxt, p, REG_X5)

		// Restore LR and REGCTXT

		// MOV 8(SP), REGCTXT
		p = obj.Appendp(p, newprog)
		p.As = AMOV
		p.From = obj.Addr{Type: obj.TYPE_MEM, Reg: REG_SP, Offset: 8}
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_CTXT}
		// MOV (SP), LR
		p = obj.Appendp(p, newprog)
		p.As = AMOV
		p.From = obj.Addr{Type: obj.TYPE_MEM, Reg: REG_SP, Offset: 0}
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_LR}
		// ADDI $16, SP
		p = obj.Appendp(p, newprog)
		p.As = AADDI
		p.From = obj.Addr{Type: obj.TYPE_CONST, Offset: frameSize}
		p.Reg = REG_SP
		p.To = obj.Addr{Type: obj.TYPE_REG, Reg: REG_SP}
		p.Spadj = -frameSize

		// Unspill arguments
		p = cursym.Func().UnspillRegisterArgs(p, newprog)
		p = ctxt.EndUnsafePoint(p, newprog, -1)
	}

	// Jump back to here after morestack returns.
	startPred := p

	// MOV	g_stackguard(g), X6
	p = obj.Appendp(p, newprog)
	p.As = AMOV
	p.From.Type = obj.TYPE_MEM
	p.From.Reg = REGG
	p.From.Offset = 2 * int64(ctxt.Arch.PtrSize) // G.stackguard0
	if cursym.CFunc() {
		p.From.Offset = 3 * int64(ctxt.Arch.PtrSize) // G.stackguard1
	}
	p.To.Type = obj.TYPE_REG
	p.To.Reg = REG_X6

	// Mark the stack bound check and morestack call async nonpreemptible.
	// If we get preempted here, when resumed the preemption request is
	// cleared, but we'll still call morestack, which will double the stack
	// unnecessarily. See issue #35470.
	p = ctxt.StartUnsafePoint(p, newprog)

	var to_done, to_more *obj.Prog

	if framesize <= abi.StackSmall {
		// small stack
		//	// if SP > stackguard { goto done }
		//	BLTU	stackguard, SP, done
		p = obj.Appendp(p, newprog)
		p.As = ABLTU
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_X6
		p.Reg = REG_SP
		p.To.Type = obj.TYPE_BRANCH
		to_done = p
	} else {
		// large stack: SP-framesize < stackguard-StackSmall
		offset := int64(framesize) - abi.StackSmall
		if framesize > abi.StackBig {
			// Such a large stack we need to protect against underflow.
			// The runtime guarantees SP > objabi.StackBig, but
			// framesize is large enough that SP-framesize may
			// underflow, causing a direct comparison with the
			// stack guard to incorrectly succeed. We explicitly
			// guard against underflow.
			//
			//	MOV	$(framesize-StackSmall), X7
			//	BLTU	SP, X7, label-of-call-to-morestack

			p = obj.Appendp(p, newprog)
			p.As = AMOV
			p.From.Type = obj.TYPE_CONST
			p.From.Offset = offset
			p.To.Type = obj.TYPE_REG
			p.To.Reg = REG_X7

			p = obj.Appendp(p, newprog)
			p.As = ABLTU
			p.From.Type = obj.TYPE_REG
			p.From.Reg = REG_SP
			p.Reg = REG_X7
			p.To.Type = obj.TYPE_BRANCH
			to_more = p
		}

		// Check against the stack guard. We've ensured this won't underflow.
		//	ADD	$-(framesize-StackSmall), SP, X7
		//	// if X7 > stackguard { goto done }
		//	BLTU	stackguard, X7, done
		p = obj.Appendp(p, newprog)
		p.As = AADDI
		p.From.Type = obj.TYPE_CONST
		p.From.Offset = -offset
		p.Reg = REG_SP
		p.To.Type = obj.TYPE_REG
		p.To.Reg = REG_X7

		p = obj.Appendp(p, newprog)
		p.As = ABLTU
		p.From.Type = obj.TYPE_REG
		p.From.Reg = REG_X6
		p.Reg = REG_X7
		p.To.Type = obj.TYPE_BRANCH
		to_done = p
	}

	// Spill the register args that could be clobbered by the
	// morestack code
	p = ctxt.EmitEntryStackMap(cursym, p, newprog)
	p = cursym.Func().SpillRegisterArgs(p, newprog)

	// CALL runtime.morestack(SB)
	p = obj.Appendp(p, newprog)
	p.As = obj.ACALL
	p.To.Type = obj.TYPE_BRANCH

	if cursym.CFunc() {
		p.To.Sym = ctxt.Lookup("runtime.morestackc")
	} else if !cursym.Func().Text.From.Sym.NeedCtxt() {
		p.To.Sym = ctxt.Lookup("runtime.morestack_noctxt")
	} else {
		p.To.Sym = ctxt.Lookup("runtime.morestack")
	}
	if to_more != nil {
		to_more.To.SetTarget(p)
	}
	jalToSym(ctxt, p, REG_X5)

	// The instructions which unspill regs should be preemptible.
	p = ctxt.EndUnsafePoint(p, newprog, -1)
	p = cursym.Func().UnspillRegisterArgs(p, newprog)

	// JMP start
	p = obj.Appendp(p, newprog)
	p.As = AJAL
	p.To = obj.Addr{Type: obj.TYPE_BRANCH}
	p.From = obj.Addr{Type: obj.TYPE_REG, Reg: REG_ZERO}
	p.To.SetTarget(startPred.Link)

	// placeholder for to_done's jump target
	p = obj.Appendp(p, newprog)
	p.As = obj.ANOP // zero-width place holder
	to_done.To.SetTarget(p)

	return p
}

// signExtend sign extends val starting at bit bit.
func signExtend(val int64, bit uint) int64 {
	return val << (64 - bit) >> (64 - bit)
}

// Split32BitImmediate splits a signed 32-bit immediate into a signed 20-bit
// upper immediate and a signed 12-bit lower immediate to be added to the upper
// result. For example, high may be used in LUI and low in a following ADDI to
// generate a full 32-bit constant.
func Split32BitImmediate(imm int64) (low, high int64, err error) {
	if err := immIFits(imm, 32); err != nil {
		return 0, 0, err
	}

	// Nothing special needs to be done if the immediate fits in 12 bits.
	if err := immIFits(imm, 12); err == nil {
		return imm, 0, nil
	}

	high = imm >> 12

	// The bottom 12 bits will be treated as signed.
	//
	// If that will result in a negative 12 bit number, add 1 to
	// our upper bits to adjust for the borrow.
	//
	// It is not possible for this increment to overflow. To
	// overflow, the 20 top bits would be 1, and the sign bit for
	// the low 12 bits would be set, in which case the entire 32
	// bit pattern fits in a 12 bit signed value.
	if imm&(1<<11) != 0 {
		high++
	}

	low = signExtend(imm, 12)
	high = signExtend(high, 20)

	return low, high, nil
}

func regVal(r, min, max uint32) uint32 {
	if r < min || r > max {
		panic(fmt.Sprintf("register out of range, want %d <= %d <= %d", min, r, max))
	}
	return r - min
}

// regI returns an integer register.
func regI(r uint32) uint32 {
	return regVal(r, REG_X0, REG_X31)
}

// regF returns a float register.
func regF(r uint32) uint32 {
	return regVal(r, REG_F0, REG_F31)
}

// regV returns a vector register.
func regV(r uint32) uint32 {
	return regVal(r, REG_V0, REG_V31)
}

// regAddr extracts a register from an Addr.
func regAddr(a obj.Addr, min, max uint32) uint32 {
	if a.Type != obj.TYPE_REG {
		panic(fmt.Sprintf("ill typed: %+v", a))
	}
	return regVal(uint32(a.Reg), min, max)
}

// regIAddr extracts the integer register from an Addr.
func regIAddr(a obj.Addr) uint32 {
	return regAddr(a, REG_X0, REG_X31)
}

// regFAddr extracts the float register from an Addr.
func regFAddr(a obj.Addr) uint32 {
	return regAddr(a, REG_F0, REG_F31)
}

// immEven checks that the immediate is a multiple of two. If it
// is not, an error is returned.
func immEven(x int64) error {
	if x&1 != 0 {
		return fmt.Errorf("immediate %#x is not a multiple of two", x)
	}
	return nil
}

// immIFits checks whether the immediate value x fits in nbits bits
// as a signed integer. If it does not, an error is returned.
func immIFits(x int64, nbits uint) error {
	nbits--
	min := int64(-1) << nbits
	max := int64(1)<<nbits - 1
	if x < min || x > max {
		if nbits <= 16 {
			return fmt.Errorf("signed immediate %d must be in range [%d, %d] (%d bits)", x, min, max, nbits)
		}
		return fmt.Errorf("signed immediate %#x must be in range [%#x, %#x] (%d bits)", x, min, max, nbits)
	}
	return nil
}

// immI extracts the signed integer of the specified size from an immediate.
func immI(as obj.As, imm int64, nbits uint) uint32 {
	if err := immIFits(imm, nbits); err != nil {
		panic(fmt.Sprintf("%v: %v", as, err))
	}
	return uint32(imm)
}

func wantImmI(ctxt *obj.Link, ins *instruction, imm int64, nbits uint) {
	if err := immIFits(imm, nbits); err != nil {
		ctxt.Diag("%v: %v", ins, err)
	}
}

func wantReg(ctxt *obj.Link, ins *instruction, pos string, descr string, r, min, max uint32) {
	if r < min || r > max {
		var suffix string
		if r != obj.REG_NONE {
			suffix = fmt.Sprintf(" but got non-%s register %s", descr, RegName(int(r)))
		}
		ctxt.Diag("%v: expected %s register in %s position%s", ins, descr, pos, suffix)
	}
}

func wantNoneReg(ctxt *obj.Link, ins *instruction, pos string, r uint32) {
	if r != obj.REG_NONE {
		ctxt.Diag("%v: expected no register in %s but got register %s", ins, pos, RegName(int(r)))
	}
}

// wantIntReg checks that r is an integer register.
func wantIntReg(ctxt *obj.Link, ins *instruction, pos string, r uint32) {
	wantReg(ctxt, ins, pos, "integer", r, REG_X0, REG_X31)
}

// wantFloatReg checks that r is a floating-point register.
func wantFloatReg(ctxt *obj.Link, ins *instruction, pos string, r uint32) {
	wantReg(ctxt, ins, pos, "float", r, REG_F0, REG_F31)
}

// wantVectorReg checks that r is a vector register.
func wantVectorReg(ctxt *obj.Link, ins *instruction, pos string, r uint32) {
	wantReg(ctxt, ins, pos, "vector", r, REG_V0, REG_V31)
}

// wantEvenOffset checks that the offset is a multiple of two.
func wantEvenOffset(ctxt *obj.Link, ins *instruction, offset int64) {
	if err := immEven(offset); err != nil {
		ctxt.Diag("%v: %v", ins, err)
	}
}

func validateRII(ctxt *obj.Link, ins *instruction) {
	wantIntReg(ctxt, ins, "rd", ins.rd)
	wantIntReg(ctxt, ins, "rs1", ins.rs1)
	wantNoneReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateRIII(ctxt *obj.Link, ins *instruction) {
	wantIntReg(ctxt, ins, "rd", ins.rd)
	wantIntReg(ctxt, ins, "rs1", ins.rs1)
	wantIntReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateRFFF(ctxt *obj.Link, ins *instruction) {
	wantFloatReg(ctxt, ins, "rd", ins.rd)
	wantFloatReg(ctxt, ins, "rs1", ins.rs1)
	wantFloatReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateRFFFF(ctxt *obj.Link, ins *instruction) {
	wantFloatReg(ctxt, ins, "rd", ins.rd)
	wantFloatReg(ctxt, ins, "rs1", ins.rs1)
	wantFloatReg(ctxt, ins, "rs2", ins.rs2)
	wantFloatReg(ctxt, ins, "rs3", ins.rs3)
}

func validateRFFI(ctxt *obj.Link, ins *instruction) {
	wantIntReg(ctxt, ins, "rd", ins.rd)
	wantFloatReg(ctxt, ins, "rs1", ins.rs1)
	wantFloatReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateRFI(ctxt *obj.Link, ins *instruction) {
	wantIntReg(ctxt, ins, "rd", ins.rd)
	wantNoneReg(ctxt, ins, "rs1", ins.rs1)
	wantFloatReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateRIF(ctxt *obj.Link, ins *instruction) {
	wantFloatReg(ctxt, ins, "rd", ins.rd)
	wantNoneReg(ctxt, ins, "rs1", ins.rs1)
	wantIntReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateRFF(ctxt *obj.Link, ins *instruction) {
	wantFloatReg(ctxt, ins, "rd", ins.rd)
	wantNoneReg(ctxt, ins, "rs1", ins.rs1)
	wantFloatReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateIII(ctxt *obj.Link, ins *instruction) {
	wantImmI(ctxt, ins, ins.imm, 12)
	wantIntReg(ctxt, ins, "rd", ins.rd)
	wantIntReg(ctxt, ins, "rs1", ins.rs1)
	wantNoneReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateIF(ctxt *obj.Link, ins *instruction) {
	wantImmI(ctxt, ins, ins.imm, 12)
	wantFloatReg(ctxt, ins, "rd", ins.rd)
	wantIntReg(ctxt, ins, "rs1", ins.rs1)
	wantNoneReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateSI(ctxt *obj.Link, ins *instruction) {
	wantImmI(ctxt, ins, ins.imm, 12)
	wantIntReg(ctxt, ins, "rd", ins.rd)
	wantIntReg(ctxt, ins, "rs1", ins.rs1)
	wantNoneReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateSF(ctxt *obj.Link, ins *instruction) {
	wantImmI(ctxt, ins, ins.imm, 12)
	wantIntReg(ctxt, ins, "rd", ins.rd)
	wantFloatReg(ctxt, ins, "rs1", ins.rs1)
	wantNoneReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateB(ctxt *obj.Link, ins *instruction) {
	// Offsets are multiples of two, so accept 13 bit immediates for the
	// 12 bit slot. We implicitly drop the least significant bit in encodeB.
	wantEvenOffset(ctxt, ins, ins.imm)
	wantImmI(ctxt, ins, ins.imm, 13)
	wantNoneReg(ctxt, ins, "rd", ins.rd)
	wantIntReg(ctxt, ins, "rs1", ins.rs1)
	wantIntReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateU(ctxt *obj.Link, ins *instruction) {
	wantImmI(ctxt, ins, ins.imm, 20)
	wantIntReg(ctxt, ins, "rd", ins.rd)
	wantNoneReg(ctxt, ins, "rs1", ins.rs1)
	wantNoneReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateJ(ctxt *obj.Link, ins *instruction) {
	// Offsets are multiples of two, so accept 21 bit immediates for the
	// 20 bit slot. We implicitly drop the least significant bit in encodeJ.
	wantEvenOffset(ctxt, ins, ins.imm)
	wantImmI(ctxt, ins, ins.imm, 21)
	wantIntReg(ctxt, ins, "rd", ins.rd)
	wantNoneReg(ctxt, ins, "rs1", ins.rs1)
	wantNoneReg(ctxt, ins, "rs2", ins.rs2)
	wantNoneReg(ctxt, ins, "rs3", ins.rs3)
}

func validateRaw(ctxt *obj.Link, ins *instruction) {
	// Treat the raw value specially as a 32-bit unsigned integer.
	// Nobody wants to enter negative machine code.
	if ins.imm < 0 || 1<<32 <= ins.imm {
		ctxt.Diag("%v: immediate %d in raw position cannot be larger than 32 bits", ins.as, ins.imm)
	}
}

// extractBitAndShift extracts the specified bit from the given immediate,
// before shifting it to the requested position and returning it.
func extractBitAndShift(imm uint32, bit, pos int) uint32 {
	return ((imm >> bit) & 1) << pos
}

// encodeR encodes an R-type RISC-V instruction.
func encodeR(as obj.As, rs1, rs2, rd, funct3, funct7 uint32) uint32 {
	enc := encode(as)
	if enc == nil {
		panic("encodeR: could not encode instruction")
	}
	if enc.rs2 != 0 && rs2 != 0 {
		panic("encodeR: instruction uses rs2, but rs2 was nonzero")
	}
	return funct7<<25 | enc.funct7<<25 | enc.rs2<<20 | rs2<<20 | rs1<<15 | enc.funct3<<12 | funct3<<12 | rd<<7 | enc.opcode
}

// encodeR4 encodes an R4-type RISC-V instruction.
func encodeR4(as obj.As, rs1, rs2, rs3, rd, funct3, funct2 uint32) uint32 {
	enc := encode(as)
	if enc == nil {
		panic("encodeR4: could not encode instruction")
	}
	if enc.rs2 != 0 {
		panic("encodeR4: instruction uses rs2")
	}
	funct2 |= enc.funct7
	if funct2&^3 != 0 {
		panic("encodeR4: funct2 requires more than 2 bits")
	}
	return rs3<<27 | funct2<<25 | rs2<<20 | rs1<<15 | enc.funct3<<12 | funct3<<12 | rd<<7 | enc.opcode
}

func encodeRII(ins *instruction) uint32 {
	return encodeR(ins.as, regI(ins.rs1), 0, regI(ins.rd), ins.funct3, ins.funct7)
}

func encodeRIII(ins *instruction) uint32 {
	return encodeR(ins.as, regI(ins.rs1), regI(ins.rs2), regI(ins.rd), ins.funct3, ins.funct7)
}

func encodeRFFF(ins *instruction) uint32 {
	return encodeR(ins.as, regF(ins.rs1), regF(ins.rs2), regF(ins.rd), ins.funct3, ins.funct7)
}

func encodeRFFFF(ins *instruction) uint32 {
	return encodeR4(ins.as, regF(ins.rs1), regF(ins.rs2), regF(ins.rs3), regF(ins.rd), ins.funct3, ins.funct7)
}

func encodeRFFI(ins *instruction) uint32 {
	return encodeR(ins.as, regF(ins.rs1), regF(ins.rs2), regI(ins.rd), ins.funct3, ins.funct7)
}

func encodeRFI(ins *instruction) uint32 {
	return encodeR(ins.as, regF(ins.rs2), 0, regI(ins.rd), ins.funct3, ins.funct7)
}

func encodeRIF(ins *instruction) uint32 {
	return encodeR(ins.as, regI(ins.rs2), 0, regF(ins.rd), ins.funct3, ins.funct7)
}

func encodeRFF(ins *instruction) uint32 {
	return encodeR(ins.as, regF(ins.rs2), 0, regF(ins.rd), ins.funct3, ins.funct7)
}

// encodeI encodes an I-type RISC-V instruction.
func encodeI(as obj.As, rs1, rd, imm uint32) uint32 {
	enc := encode(as)
	if enc == nil {
		panic("encodeI: could not encode instruction")
	}
	imm |= uint32(enc.csr)
	return imm<<20 | rs1<<15 | enc.funct3<<12 | rd<<7 | enc.opcode
}

func encodeIII(ins *instruction) uint32 {
	return encodeI(ins.as, regI(ins.rs1), regI(ins.rd), uint32(ins.imm))
}

func encodeIF(ins *instruction) uint32 {
	return encodeI(ins.as, regI(ins.rs1), regF(ins.rd), uint32(ins.imm))
}

// encodeS encodes an S-type RISC-V instruction.
func encodeS(as obj.As, rs1, rs2, imm uint32) uint32 {
	enc := encode(as)
	if enc == nil {
		panic("encodeS: could not encode instruction")
	}
	return (imm>>5)<<25 | rs2<<20 | rs1<<15 | enc.funct3<<12 | (imm&0x1f)<<7 | enc.opcode
}

func encodeSI(ins *instruction) uint32 {
	return encodeS(ins.as, regI(ins.rd), regI(ins.rs1), uint32(ins.imm))
}

func encodeSF(ins *instruction) uint32 {
	return encodeS(ins.as, regI(ins.rd), regF(ins.rs1), uint32(ins.imm))
}

// encodeBImmediate encodes an immediate for a B-type RISC-V instruction.
func encodeBImmediate(imm uint32) uint32 {
	return (imm>>12)<<31 | ((imm>>5)&0x3f)<<25 | ((imm>>1)&0xf)<<8 | ((imm>>11)&0x1)<<7
}

// encodeB encodes a B-type RISC-V instruction.
func encodeB(ins *instruction) uint32 {
	imm := immI(ins.as, ins.imm, 13)
	rs2 := regI(ins.rs1)
	rs1 := regI(ins.rs2)
	enc := encode(ins.as)
	if enc == nil {
		panic("encodeB: could not encode instruction")
	}
	return encodeBImmediate(imm) | rs2<<20 | rs1<<15 | enc.funct3<<12 | enc.opcode
}

// encodeU encodes a U-type RISC-V instruction.
func encodeU(ins *instruction) uint32 {
	// The immediates for encodeU are the upper 20 bits of a 32 bit value.
	// Rather than have the user/compiler generate a 32 bit constant, the
	// bottommost bits of which must all be zero, instead accept just the
	// top bits.
	imm := immI(ins.as, ins.imm, 20)
	rd := regI(ins.rd)
	enc := encode(ins.as)
	if enc == nil {
		panic("encodeU: could not encode instruction")
	}
	return imm<<12 | rd<<7 | enc.opcode
}

// encodeJImmediate encodes an immediate for a J-type RISC-V instruction.
func encodeJImmediate(imm uint32) uint32 {
	return (imm>>20)<<31 | ((imm>>1)&0x3ff)<<21 | ((imm>>11)&0x1)<<20 | ((imm>>12)&0xff)<<12
}

// encodeJ encodes a J-type RISC-V instruction.
func encodeJ(ins *instruction) uint32 {
	imm := immI(ins.as, ins.imm, 21)
	rd := regI(ins.rd)
	enc := encode(ins.as)
	if enc == nil {
		panic("encodeJ: could not encode instruction")
	}
	return encodeJImmediate(imm) | rd<<7 | enc.opcode
}

// encodeCBImmediate encodes an immediate for a CB-type RISC-V instruction.
func encodeCBImmediate(imm uint32) uint32 {
	// Bit order - [8|4:3|7:6|2:1|5]
	bits := extractBitAndShift(imm, 8, 7)
	bits |= extractBitAndShift(imm, 4, 6)
	bits |= extractBitAndShift(imm, 3, 5)
	bits |= extractBitAndShift(imm, 7, 4)
	bits |= extractBitAndShift(imm, 6, 3)
	bits |= extractBitAndShift(imm, 2, 2)
	bits |= extractBitAndShift(imm, 1, 1)
	bits |= extractBitAndShift(imm, 5, 0)
	return (bits>>5)<<10 | (bits&0x1f)<<2
}

// encodeCJImmediate encodes an immediate for a CJ-type RISC-V instruction.
func encodeCJImmediate(imm uint32) uint32 {
	// Bit order - [11|4|9:8|10|6|7|3:1|5]
	bits := extractBitAndShift(imm, 11, 10)
	bits |= extractBitAndShift(imm, 4, 9)
	bits |= extractBitAndShift(imm, 9, 8)
	bits |= extractBitAndShift(imm, 8, 7)
	bits |= extractBitAndShift(imm, 10, 6)
	bits |= extractBitAndShift(imm, 6, 5)
	bits |= extractBitAndShift(imm, 7, 4)
	bits |= extractBitAndShift(imm, 3, 3)
	bits |= extractBitAndShift(imm, 2, 2)
	bits |= extractBitAndShift(imm, 1, 1)
	bits |= extractBitAndShift(imm, 5, 0)
	return bits << 2
}

func encodeRawIns(ins *instruction) uint32 {
	// Treat the raw value specially as a 32-bit unsigned integer.
	// Nobody wants to enter negative machine code.
	if ins.imm < 0 || 1<<32 <= ins.imm {
		panic(fmt.Sprintf("immediate %d cannot fit in 32 bits", ins.imm))
	}
	return uint32(ins.imm)
}

func EncodeBImmediate(imm int64) (int64, error) {
	if err := immIFits(imm, 13); err != nil {
		return 0, err
	}
	if err := immEven(imm); err != nil {
		return 0, err
	}
	return int64(encodeBImmediate(uint32(imm))), nil
}

func EncodeCBImmediate(imm int64) (int64, error) {
	if err := immIFits(imm, 9); err != nil {
		return 0, err
	}
	if err := immEven(imm); err != nil {
		return 0, err
	}
	return int64(encodeCBImmediate(uint32(imm))), nil
}

func EncodeCJImmediate(imm int64) (int64, error) {
	if err := immIFits(imm, 12); err != nil {
		return 0, err
	}
	if err := immEven(imm); err != nil {
		return 0, err
	}
	return int64(encodeCJImmediate(uint32(imm))), nil
}

func EncodeIImmediate(imm int64) (int64, error) {
	if err := immIFits(imm, 12); err != nil {
		return 0, err
	}
	return imm << 20, nil
}

func EncodeJImmediate(imm int64) (int64, error) {
	if err := immIFits(imm, 21); err != nil {
		return 0, err
	}
	if err := immEven(imm); err != nil {
		return 0, err
	}
	return int64(encodeJImmediate(uint32(imm))), nil
}

func EncodeSImmediate(imm int64) (int64, error) {
	if err := immIFits(imm, 12); err != nil {
		return 0, err
	}
	return ((imm >> 5) << 25) | ((imm & 0x1f) << 7), nil
}

func EncodeUImmediate(imm int64) (int64, error) {
	if err := immIFits(imm, 20); err != nil {
		return 0, err
	}
	return imm << 12, nil
}

type encoding struct {
	encode   func(*instruction) uint32     // encode returns the machine code for an instruction
	validate func(*obj.Link, *instruction) // validate validates an instruction
	length   int                           // length of encoded instruction; 0 for pseudo-ops, 4 otherwise
}

var (
	// Encodings have the following naming convention:
	//
	//  1. the instruction encoding (R/I/S/B/U/J), in lowercase
	//  2. zero or more register operand identifiers (I = integer
	//     register, F = float register), in uppercase
	//  3. the word "Encoding"
	//
	// For example, rIIIEncoding indicates an R-type instruction with two
	// integer register inputs and an integer register output; sFEncoding
	// indicates an S-type instruction with rs2 being a float register.

	rIIIEncoding  = encoding{encode: encodeRIII, validate: validateRIII, length: 4}
	rIIEncoding   = encoding{encode: encodeRII, validate: validateRII, length: 4}
	rFFFEncoding  = encoding{encode: encodeRFFF, validate: validateRFFF, length: 4}
	rFFFFEncoding = encoding{encode: encodeRFFFF, validate: validateRFFFF, length: 4}
	rFFIEncoding  = encoding{encode: encodeRFFI, validate: validateRFFI, length: 4}
	rFIEncoding   = encoding{encode: encodeRFI, validate: validateRFI, length: 4}
	rIFEncoding   = encoding{encode: encodeRIF, validate: validateRIF, length: 4}
	rFFEncoding   = encoding{encode: encodeRFF, validate: validateRFF, length: 4}

	iIIEncoding = encoding{encode: encodeIII, validate: validateIII, length: 4}
	iFEncoding  = encoding{encode: encodeIF, validate: validateIF, length: 4}

	sIEncoding = encoding{encode: encodeSI, validate: validateSI, length: 4}
	sFEncoding = encoding{encode: encodeSF, validate: validateSF, length: 4}

	bEncoding = encoding{encode: encodeB, validate: validateB, length: 4}
	uEncoding = encoding{encode: encodeU, validate: validateU, length: 4}
	jEncoding = encoding{encode: encodeJ, validate: validateJ, length: 4}

	// rawEncoding encodes a raw instruction byte sequence.
	rawEncoding = encoding{encode: encodeRawIns, validate: validateRaw, length: 4}

	// pseudoOpEncoding panics if encoding is attempted, but does no validation.
	pseudoOpEncoding = encoding{encode: nil, validate: func(*obj.Link, *instruction) {}, length: 0}

	// badEncoding is used when an invalid op is encountered.
	// An error has already been generated, so let anything else through.
	badEncoding = encoding{encode: func(*instruction) uint32 { return 0 }, validate: func(*obj.Link, *instruction) {}, length: 0}
)

// instructionData specifies details relating to a RISC-V instruction.
type instructionData struct {
	enc     encoding
	immForm obj.As // immediate form of this instruction
	ternary bool
}

// instructions contains details of RISC-V instructions, including
// their encoding type. Entries are masked with obj.AMask to keep
// indices small.
var instructions = [ALAST & obj.AMask]instructionData{
	// Unprivileged ISA

	// 2.4: Integer Computational Instructions
	AADDI & obj.AMask:  {enc: iIIEncoding, ternary: true},
	ASLTI & obj.AMask:  {enc: iIIEncoding, ternary: true},
	ASLTIU & obj.AMask: {enc: iIIEncoding, ternary: true},
	AANDI & obj.AMask:  {enc: iIIEncoding, ternary: true},
	AORI & obj.AMask:   {enc: iIIEncoding, ternary: true},
	AXORI & obj.AMask:  {enc: iIIEncoding, ternary: true},
	ASLLI & obj.AMask:  {enc: iIIEncoding, ternary: true},
	ASRLI & obj.AMask:  {enc: iIIEncoding, ternary: true},
	ASRAI & obj.AMask:  {enc: iIIEncoding, ternary: true},
	ALUI & obj.AMask:   {enc: uEncoding},
	AAUIPC & obj.AMask: {enc: uEncoding},
	AADD & obj.AMask:   {enc: rIIIEncoding, immForm: AADDI, ternary: true},
	ASLT & obj.AMask:   {enc: rIIIEncoding, immForm: ASLTI, ternary: true},
	ASLTU & obj.AMask:  {enc: rIIIEncoding, immForm: ASLTIU, ternary: true},
	AAND & obj.AMask:   {enc: rIIIEncoding, immForm: AANDI, ternary: true},
	AOR & obj.AMask:    {enc: rIIIEncoding, immForm: AORI, ternary: true},
	AXOR & obj.AMask:   {enc: rIIIEncoding, immForm: AXORI, ternary: true},
	ASLL & obj.AMask:   {enc: rIIIEncoding, immForm: ASLLI, ternary: true},
	ASRL & obj.AMask:   {enc: rIIIEncoding, immForm: ASRLI, ternary: true},
	ASUB & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	ASRA & obj.AMask:   {enc: rIIIEncoding, immForm: ASRAI, ternary: true},

	// 2.5: Control Transfer Instructions
	AJAL & obj.AMask:  {enc: jEncoding},
	AJALR & obj.AMask: {enc: iIIEncoding},
	ABEQ & obj.AMask:  {enc: bEncoding},
	ABNE & obj.AMask:  {enc: bEncoding},
	ABLT & obj.AMask:  {enc: bEncoding},
	ABLTU & obj.AMask: {enc: bEncoding},
	ABGE & obj.AMask:  {enc: bEncoding},
	ABGEU & obj.AMask: {enc: bEncoding},

	// 2.6: Load and Store Instructions
	ALW & obj.AMask:  {enc: iIIEncoding},
	ALWU & obj.AMask: {enc: iIIEncoding},
	ALH & obj.AMask:  {enc: iIIEncoding},
	ALHU & obj.AMask: {enc: iIIEncoding},
	ALB & obj.AMask:  {enc: iIIEncoding},
	ALBU & obj.AMask: {enc: iIIEncoding},
	ASW & obj.AMask:  {enc: sIEncoding},
	ASH & obj.AMask:  {enc: sIEncoding},
	ASB & obj.AMask:  {enc: sIEncoding},

	// 2.7: Memory Ordering
	AFENCE & obj.AMask: {enc: iIIEncoding},

	// 5.2: Integer Computational Instructions (RV64I)
	AADDIW & obj.AMask: {enc: iIIEncoding, ternary: true},
	ASLLIW & obj.AMask: {enc: iIIEncoding, ternary: true},
	ASRLIW & obj.AMask: {enc: iIIEncoding, ternary: true},
	ASRAIW & obj.AMask: {enc: iIIEncoding, ternary: true},
	AADDW & obj.AMask:  {enc: rIIIEncoding, immForm: AADDIW, ternary: true},
	ASLLW & obj.AMask:  {enc: rIIIEncoding, immForm: ASLLIW, ternary: true},
	ASRLW & obj.AMask:  {enc: rIIIEncoding, immForm: ASRLIW, ternary: true},
	ASUBW & obj.AMask:  {enc: rIIIEncoding, ternary: true},
	ASRAW & obj.AMask:  {enc: rIIIEncoding, immForm: ASRAIW, ternary: true},

	// 5.3: Load and Store Instructions (RV64I)
	ALD & obj.AMask: {enc: iIIEncoding},
	ASD & obj.AMask: {enc: sIEncoding},

	// 7.1: CSR Instructions
	ACSRRS & obj.AMask: {enc: iIIEncoding},

	// 7.1: Multiplication Operations
	AMUL & obj.AMask:    {enc: rIIIEncoding, ternary: true},
	AMULH & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	AMULHU & obj.AMask:  {enc: rIIIEncoding, ternary: true},
	AMULHSU & obj.AMask: {enc: rIIIEncoding, ternary: true},
	AMULW & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	ADIV & obj.AMask:    {enc: rIIIEncoding, ternary: true},
	ADIVU & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	AREM & obj.AMask:    {enc: rIIIEncoding, ternary: true},
	AREMU & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	ADIVW & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	ADIVUW & obj.AMask:  {enc: rIIIEncoding, ternary: true},
	AREMW & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	AREMUW & obj.AMask:  {enc: rIIIEncoding, ternary: true},

	// 8.2: Load-Reserved/Store-Conditional
	ALRW & obj.AMask: {enc: rIIIEncoding},
	ALRD & obj.AMask: {enc: rIIIEncoding},
	ASCW & obj.AMask: {enc: rIIIEncoding},
	ASCD & obj.AMask: {enc: rIIIEncoding},

	// 8.3: Atomic Memory Operations
	AAMOSWAPW & obj.AMask: {enc: rIIIEncoding},
	AAMOSWAPD & obj.AMask: {enc: rIIIEncoding},
	AAMOADDW & obj.AMask:  {enc: rIIIEncoding},
	AAMOADDD & obj.AMask:  {enc: rIIIEncoding},
	AAMOANDW & obj.AMask:  {enc: rIIIEncoding},
	AAMOANDD & obj.AMask:  {enc: rIIIEncoding},
	AAMOORW & obj.AMask:   {enc: rIIIEncoding},
	AAMOORD & obj.AMask:   {enc: rIIIEncoding},
	AAMOXORW & obj.AMask:  {enc: rIIIEncoding},
	AAMOXORD & obj.AMask:  {enc: rIIIEncoding},
	AAMOMAXW & obj.AMask:  {enc: rIIIEncoding},
	AAMOMAXD & obj.AMask:  {enc: rIIIEncoding},
	AAMOMAXUW & obj.AMask: {enc: rIIIEncoding},
	AAMOMAXUD & obj.AMask: {enc: rIIIEncoding},
	AAMOMINW & obj.AMask:  {enc: rIIIEncoding},
	AAMOMIND & obj.AMask:  {enc: rIIIEncoding},
	AAMOMINUW & obj.AMask: {enc: rIIIEncoding},
	AAMOMINUD & obj.AMask: {enc: rIIIEncoding},

	// 11.5: Single-Precision Load and Store Instructions
	AFLW & obj.AMask: {enc: iFEncoding},
	AFSW & obj.AMask: {enc: sFEncoding},

	// 11.6: Single-Precision Floating-Point Computational Instructions
	AFADDS & obj.AMask:   {enc: rFFFEncoding},
	AFSUBS & obj.AMask:   {enc: rFFFEncoding},
	AFMULS & obj.AMask:   {enc: rFFFEncoding},
	AFDIVS & obj.AMask:   {enc: rFFFEncoding},
	AFMINS & obj.AMask:   {enc: rFFFEncoding},
	AFMAXS & obj.AMask:   {enc: rFFFEncoding},
	AFSQRTS & obj.AMask:  {enc: rFFFEncoding},
	AFMADDS & obj.AMask:  {enc: rFFFFEncoding},
	AFMSUBS & obj.AMask:  {enc: rFFFFEncoding},
	AFNMSUBS & obj.AMask: {enc: rFFFFEncoding},
	AFNMADDS & obj.AMask: {enc: rFFFFEncoding},

	// 11.7: Single-Precision Floating-Point Conversion and Move Instructions
	AFCVTWS & obj.AMask:  {enc: rFIEncoding},
	AFCVTLS & obj.AMask:  {enc: rFIEncoding},
	AFCVTSW & obj.AMask:  {enc: rIFEncoding},
	AFCVTSL & obj.AMask:  {enc: rIFEncoding},
	AFCVTWUS & obj.AMask: {enc: rFIEncoding},
	AFCVTLUS & obj.AMask: {enc: rFIEncoding},
	AFCVTSWU & obj.AMask: {enc: rIFEncoding},
	AFCVTSLU & obj.AMask: {enc: rIFEncoding},
	AFSGNJS & obj.AMask:  {enc: rFFFEncoding},
	AFSGNJNS & obj.AMask: {enc: rFFFEncoding},
	AFSGNJXS & obj.AMask: {enc: rFFFEncoding},
	AFMVXW & obj.AMask:   {enc: rFIEncoding},
	AFMVWX & obj.AMask:   {enc: rIFEncoding},

	// 11.8: Single-Precision Floating-Point Compare Instructions
	AFEQS & obj.AMask: {enc: rFFIEncoding},
	AFLTS & obj.AMask: {enc: rFFIEncoding},
	AFLES & obj.AMask: {enc: rFFIEncoding},

	// 11.9: Single-Precision Floating-Point Classify Instruction
	AFCLASSS & obj.AMask: {enc: rFIEncoding},

	// 12.3: Double-Precision Load and Store Instructions
	AFLD & obj.AMask: {enc: iFEncoding},
	AFSD & obj.AMask: {enc: sFEncoding},

	// 12.4: Double-Precision Floating-Point Computational Instructions
	AFADDD & obj.AMask:   {enc: rFFFEncoding},
	AFSUBD & obj.AMask:   {enc: rFFFEncoding},
	AFMULD & obj.AMask:   {enc: rFFFEncoding},
	AFDIVD & obj.AMask:   {enc: rFFFEncoding},
	AFMIND & obj.AMask:   {enc: rFFFEncoding},
	AFMAXD & obj.AMask:   {enc: rFFFEncoding},
	AFSQRTD & obj.AMask:  {enc: rFFFEncoding},
	AFMADDD & obj.AMask:  {enc: rFFFFEncoding},
	AFMSUBD & obj.AMask:  {enc: rFFFFEncoding},
	AFNMSUBD & obj.AMask: {enc: rFFFFEncoding},
	AFNMADDD & obj.AMask: {enc: rFFFFEncoding},

	// 12.5: Double-Precision Floating-Point Conversion and Move Instructions
	AFCVTWD & obj.AMask:  {enc: rFIEncoding},
	AFCVTLD & obj.AMask:  {enc: rFIEncoding},
	AFCVTDW & obj.AMask:  {enc: rIFEncoding},
	AFCVTDL & obj.AMask:  {enc: rIFEncoding},
	AFCVTWUD & obj.AMask: {enc: rFIEncoding},
	AFCVTLUD & obj.AMask: {enc: rFIEncoding},
	AFCVTDWU & obj.AMask: {enc: rIFEncoding},
	AFCVTDLU & obj.AMask: {enc: rIFEncoding},
	AFCVTSD & obj.AMask:  {enc: rFFEncoding},
	AFCVTDS & obj.AMask:  {enc: rFFEncoding},
	AFSGNJD & obj.AMask:  {enc: rFFFEncoding},
	AFSGNJND & obj.AMask: {enc: rFFFEncoding},
	AFSGNJXD & obj.AMask: {enc: rFFFEncoding},
	AFMVXD & obj.AMask:   {enc: rFIEncoding},
	AFMVDX & obj.AMask:   {enc: rIFEncoding},

	// 12.6: Double-Precision Floating-Point Compare Instructions
	AFEQD & obj.AMask: {enc: rFFIEncoding},
	AFLTD & obj.AMask: {enc: rFFIEncoding},
	AFLED & obj.AMask: {enc: rFFIEncoding},

	// 12.7: Double-Precision Floating-Point Classify Instruction
	AFCLASSD & obj.AMask: {enc: rFIEncoding},

	// Privileged ISA

	// 3.2.1: Environment Call and Breakpoint
	AECALL & obj.AMask:  {enc: iIIEncoding},
	AEBREAK & obj.AMask: {enc: iIIEncoding},

	//
	// RISC-V Bit-Manipulation ISA-extensions (1.0)
	//

	// 1.1: Address Generation Instructions (Zba)
	AADDUW & obj.AMask:    {enc: rIIIEncoding, ternary: true},
	ASH1ADD & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	ASH1ADDUW & obj.AMask: {enc: rIIIEncoding, ternary: true},
	ASH2ADD & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	ASH2ADDUW & obj.AMask: {enc: rIIIEncoding, ternary: true},
	ASH3ADD & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	ASH3ADDUW & obj.AMask: {enc: rIIIEncoding, ternary: true},
	ASLLIUW & obj.AMask:   {enc: iIIEncoding, ternary: true},

	// 1.2: Basic Bit Manipulation (Zbb)
	AANDN & obj.AMask:  {enc: rIIIEncoding, ternary: true},
	ACLZ & obj.AMask:   {enc: rIIEncoding},
	ACLZW & obj.AMask:  {enc: rIIEncoding},
	ACPOP & obj.AMask:  {enc: rIIEncoding},
	ACPOPW & obj.AMask: {enc: rIIEncoding},
	ACTZ & obj.AMask:   {enc: rIIEncoding},
	ACTZW & obj.AMask:  {enc: rIIEncoding},
	AMAX & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	AMAXU & obj.AMask:  {enc: rIIIEncoding, ternary: true},
	AMIN & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	AMINU & obj.AMask:  {enc: rIIIEncoding, ternary: true},
	AORN & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	ASEXTB & obj.AMask: {enc: rIIEncoding},
	ASEXTH & obj.AMask: {enc: rIIEncoding},
	AXNOR & obj.AMask:  {enc: rIIIEncoding, ternary: true},
	AZEXTH & obj.AMask: {enc: rIIEncoding},

	// 1.3: Bitwise Rotation (Zbb)
	AROL & obj.AMask:   {enc: rIIIEncoding, ternary: true},
	AROLW & obj.AMask:  {enc: rIIIEncoding, ternary: true},
	AROR & obj.AMask:   {enc: rIIIEncoding, immForm: ARORI, ternary: true},
	ARORI & obj.AMask:  {enc: iIIEncoding, ternary: true},
	ARORIW & obj.AMask: {enc: iIIEncoding, ternary: true},
	ARORW & obj.AMask:  {enc: rIIIEncoding, immForm: ARORIW, ternary: true},
	AORCB & obj.AMask:  {enc: iIIEncoding},
	AREV8 & obj.AMask:  {enc: iIIEncoding},

	// 1.5: Single-bit Instructions (Zbs)
	ABCLR & obj.AMask:  {enc: rIIIEncoding, immForm: ABCLRI, ternary: true},
	ABCLRI & obj.AMask: {enc: iIIEncoding, ternary: true},
	ABEXT & obj.AMask:  {enc: rIIIEncoding, immForm: ABEXTI, ternary: true},
	ABEXTI & obj.AMask: {enc: iIIEncoding, ternary: true},
	ABINV & obj.AMask:  {enc: rIIIEncoding, immForm: ABINVI, ternary: true},
	ABINVI & obj.AMask: {enc: iIIEncoding, ternary: true},
	ABSET & obj.AMask:  {enc: rIIIEncoding, immForm: ABSETI, ternary: true},
	ABSETI & obj.AMask: {enc: iIIEncoding, ternary: true},

	// Escape hatch
	AWORD & obj.AMask: {enc: rawEncoding},

	// Pseudo-operations
	obj.AFUNCDATA: {enc: pseudoOpEncoding},
	obj.APCDATA:   {enc: pseudoOpEncoding},
	obj.ATEXT:     {enc: pseudoOpEncoding},
	obj.ANOP:      {enc: pseudoOpEncoding},
	obj.ADUFFZERO: {enc: pseudoOpEncoding},
	obj.ADUFFCOPY: {enc: pseudoOpEncoding},
	obj.APCALIGN:  {enc: pseudoOpEncoding},
}

// instructionDataForAs returns the instruction data for an obj.As.
func instructionDataForAs(as obj.As) (*instructionData, error) {
	if base := as &^ obj.AMask; base != obj.ABaseRISCV && base != 0 {
		return nil, fmt.Errorf("%v is not a RISC-V instruction", as)
	}
	asi := as & obj.AMask
	if int(asi) >= len(instructions) {
		return nil, fmt.Errorf("bad RISC-V instruction %v", as)
	}
	return &instructions[asi], nil
}

// encodingForAs returns the encoding for an obj.As.
func encodingForAs(as obj.As) (*encoding, error) {
	insData, err := instructionDataForAs(as)
	if err != nil {
		return &badEncoding, err
	}
	if insData.enc.validate == nil {
		return &badEncoding, fmt.Errorf("no encoding for instruction %s", as)
	}
	return &insData.enc, nil
}

type instruction struct {
	p      *obj.Prog // Prog that instruction is for
	as     obj.As    // Assembler opcode
	rd     uint32    // Destination register
	rs1    uint32    // Source register 1
	rs2    uint32    // Source register 2
	rs3    uint32    // Source register 3
	imm    int64     // Immediate
	funct3 uint32    // Function 3
	funct7 uint32    // Function 7 (or Function 2)
}

func (ins *instruction) String() string {
	if ins.p == nil {
		return ins.as.String()
	}
	var suffix string
	if ins.p.As != ins.as {
		suffix = fmt.Sprintf(" (%v)", ins.as)
	}
	return fmt.Sprintf("%v%v", ins.p, suffix)
}

func (ins *instruction) encode() (uint32, error) {
	enc, err := encodingForAs(ins.as)
	if err != nil {
		return 0, err
	}
	if enc.length <= 0 {
		return 0, fmt.Errorf("%v: encoding called for a pseudo instruction", ins.as)
	}
	return enc.encode(ins), nil
}

func (ins *instruction) length() int {
	enc, err := encodingForAs(ins.as)
	if err != nil {
		return 0
	}
	return enc.length
}

func (ins *instruction) validate(ctxt *obj.Link) {
	enc, err := encodingForAs(ins.as)
	if err != nil {
		ctxt.Diag(err.Error())
		return
	}
	enc.validate(ctxt, ins)
}

func (ins *instruction) usesRegTmp() bool {
	return ins.rd == REG_TMP || ins.rs1 == REG_TMP || ins.rs2 == REG_TMP
}

// instructionForProg returns the default *obj.Prog to instruction mapping.
func instructionForProg(p *obj.Prog) *instruction {
	ins := &instruction{
		as:  p.As,
		rd:  uint32(p.To.Reg),
		rs1: uint32(p.Reg),
		rs2: uint32(p.From.Reg),
		imm: p.From.Offset,
	}
	if len(p.RestArgs) == 1 {
		ins.rs3 = uint32(p.RestArgs[0].Reg)
	}
	return ins
}

// instructionsForOpImmediate returns the machine instructions for an immediate
// operand. The instruction is specified by as and the source register is
// specified by rs, instead of the obj.Prog.
func instructionsForOpImmediate(p *obj.Prog, as obj.As, rs int16) []*instruction {
	// <opi> $imm, REG, TO
	ins := instructionForProg(p)
	ins.as, ins.rs1, ins.rs2 = as, uint32(rs), obj.REG_NONE

	low, high, err := Split32BitImmediate(ins.imm)
	if err != nil {
		p.Ctxt.Diag("%v: constant %d too large", p, ins.imm, err)
		return nil
	}
	if high == 0 {
		return []*instruction{ins}
	}

	// Split into two additions, if possible.
	// Do not split SP-writing instructions, as otherwise the recorded SP delta may be wrong.
	if p.Spadj == 0 && ins.as == AADDI && ins.imm >= -(1<<12) && ins.imm < 1<<12-1 {
		imm0 := ins.imm / 2
		imm1 := ins.imm - imm0

		// ADDI $(imm/2), REG, TO
		// ADDI $(imm-imm/2), TO, TO
		ins.imm = imm0
		insADDI := &instruction{as: AADDI, rd: ins.rd, rs1: ins.rd, imm: imm1}
		return []*instruction{ins, insADDI}
	}

	// LUI $high, TMP
	// ADDIW $low, TMP, TMP
	// <op> TMP, REG, TO
	insLUI := &instruction{as: ALUI, rd: REG_TMP, imm: high}
	insADDIW := &instruction{as: AADDIW, rd: REG_TMP, rs1: REG_TMP, imm: low}
	switch ins.as {
	case AADDI:
		ins.as = AADD
	case AANDI:
		ins.as = AAND
	case AORI:
		ins.as = AOR
	case AXORI:
		ins.as = AXOR
	default:
		p.Ctxt.Diag("unsupported immediate instruction %v for splitting", p)
		return nil
	}
	ins.rs2 = REG_TMP
	if low == 0 {
		return []*instruction{insLUI, ins}
	}
	return []*instruction{insLUI, insADDIW, ins}
}

// instructionsForLoad returns the machine instructions for a load. The load
// instruction is specified by as and the base/source register is specified
// by rs, instead of the obj.Prog.
func instructionsForLoad(p *obj.Prog, as obj.As, rs int16) []*instruction {
	if p.From.Type != obj.TYPE_MEM {
		p.Ctxt.Diag("%v requires memory for source", p)
		return nil
	}

	switch as {
	case ALD, ALB, ALH, ALW, ALBU, ALHU, ALWU, AFLW, AFLD:
	default:
		p.Ctxt.Diag("%v: unknown load instruction %v", p, as)
		return nil
	}

	// <load> $imm, REG, TO (load $imm+(REG), TO)
	ins := instructionForProg(p)
	ins.as, ins.rs1, ins.rs2 = as, uint32(rs), obj.REG_NONE
	ins.imm = p.From.Offset

	low, high, err := Split32BitImmediate(ins.imm)
	if err != nil {
		p.Ctxt.Diag("%v: constant %d too large", p, ins.imm)
		return nil
	}
	if high == 0 {
		return []*instruction{ins}
	}

	// LUI $high, TMP
	// ADD TMP, REG, TMP
	// <load> $low, TMP, TO
	insLUI := &instruction{as: ALUI, rd: REG_TMP, imm: high}
	insADD := &instruction{as: AADD, rd: REG_TMP, rs1: REG_TMP, rs2: ins.rs1}
	ins.rs1, ins.imm = REG_TMP, low

	return []*instruction{insLUI, insADD, ins}
}

// instructionsForStore returns the machine instructions for a store. The store
// instruction is specified by as and the target/source register is specified
// by rd, instead of the obj.Prog.
func instructionsForStore(p *obj.Prog, as obj.As, rd int16) []*instruction {
	if p.To.Type != obj.TYPE_MEM {
		p.Ctxt.Diag("%v requires memory for destination", p)
		return nil
	}

	switch as {
	case ASW, ASH, ASB, ASD, AFSW, AFSD:
	default:
		p.Ctxt.Diag("%v: unknown store instruction %v", p, as)
		return nil
	}

	// <store> $imm, REG, TO (store $imm+(TO), REG)
	ins := instructionForProg(p)
	ins.as, ins.rd, ins.rs1, ins.rs2 = as, uint32(rd), uint32(p.From.Reg), obj.REG_NONE
	ins.imm = p.To.Offset

	low, high, err := Split32BitImmediate(ins.imm)
	if err != nil {
		p.Ctxt.Diag("%v: constant %d too large", p, ins.imm)
		return nil
	}
	if high == 0 {
		return []*instruction{ins}
	}

	// LUI $high, TMP
	// ADD TMP, TO, TMP
	// <store> $low, REG, TMP
	insLUI := &instruction{as: ALUI, rd: REG_TMP, imm: high}
	insADD := &instruction{as: AADD, rd: REG_TMP, rs1: REG_TMP, rs2: ins.rd}
	ins.rd, ins.imm = REG_TMP, low

	return []*instruction{insLUI, insADD, ins}
}

func instructionsForTLS(p *obj.Prog, ins *instruction) []*instruction {
	insAddTP := &instruction{as: AADD, rd: REG_TMP, rs1: REG_TMP, rs2: REG_TP}

	var inss []*instruction
	if p.Ctxt.Flag_shared {
		// TLS initial-exec mode - load TLS offset from GOT, add the thread pointer
		// register, then load from or store to the resulting memory location.
		insAUIPC := &instruction{as: AAUIPC, rd: REG_TMP}
		insLoadTLSOffset := &instruction{as: ALD, rd: REG_TMP, rs1: REG_TMP}
		inss = []*instruction{insAUIPC, insLoadTLSOffset, insAddTP, ins}
	} else {
		// TLS local-exec mode - load upper TLS offset, add the lower TLS offset,
		// add the thread pointer register, then load from or store to the resulting
		// memory location. Note that this differs from the suggested three
		// instruction sequence, as the Go linker does not currently have an
		// easy way to handle relocation across 12 bytes of machine code.
		insLUI := &instruction{as: ALUI, rd: REG_TMP}
		insADDIW := &instruction{as: AADDIW, rd: REG_TMP, rs1: REG_TMP}
		inss = []*instruction{insLUI, insADDIW, insAddTP, ins}
	}
	return inss
}

func instructionsForTLSLoad(p *obj.Prog) []*instruction {
	if p.From.Sym.Type != objabi.STLSBSS {
		p.Ctxt.Diag("%v: %v is not a TLS symbol", p, p.From.Sym)
		return nil
	}

	ins := instructionForProg(p)
	ins.as, ins.rs1, ins.rs2, ins.imm = movToLoad(p.As), REG_TMP, obj.REG_NONE, 0

	return instructionsForTLS(p, ins)
}

func instructionsForTLSStore(p *obj.Prog) []*instruction {
	if p.To.Sym.Type != objabi.STLSBSS {
		p.Ctxt.Diag("%v: %v is not a TLS symbol", p, p.To.Sym)
		return nil
	}

	ins := instructionForProg(p)
	ins.as, ins.rd, ins.rs1, ins.rs2, ins.imm = movToStore(p.As), REG_TMP, uint32(p.From.Reg), obj.REG_NONE, 0

	return instructionsForTLS(p, ins)
}

// instructionsForMOV returns the machine instructions for an *obj.Prog that
// uses a MOV pseudo-instruction.
func instructionsForMOV(p *obj.Prog) []*instruction {
	ins := instructionForProg(p)
	inss := []*instruction{ins}

	if p.Reg != 0 {
		p.Ctxt.Diag("%v: illegal MOV instruction", p)
		return nil
	}

	switch {
	case p.From.Type == obj.TYPE_CONST && p.To.Type == obj.TYPE_REG:
		// Handle constant to register moves.
		if p.As != AMOV {
			p.Ctxt.Diag("%v: unsupported constant load", p)
			return nil
		}

		// For constants larger than 32 bits in size that have trailing zeros,
		// use the value with the trailing zeros removed and then use a SLLI
		// instruction to restore the original constant.
		// For example:
		// 	MOV $0x8000000000000000, X10
		// beco
```