Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The core purpose is to take a raw instruction (`Inst`) and convert it into a human-readable assembly instruction string using GNU/AT&T syntax. A key aspect is handling "extended mnemonics."

2. **Identify Key Components:** The code clearly defines several structures (`typ1ExtndMnics`, `typ2ExtndMnics`, etc.) and a function `HandleExtndMnemonic`. These are the building blocks of the logic. The `GNUSyntax` function also stands out as the final formatting step.

3. **Analyze the Structures:**  Each `typNExtndMnics` structure represents a category of instructions with extended mnemonics. The naming convention is a good clue. Notice the common fields:
    * `BaseOpStr`: The base instruction name (e.g., "bc").
    * `ExtnOpStr`: The extended mnemonic (e.g., "bo").
    * `ValueN`, `OffsetN`: These seem related to specific fields within the instruction's encoding that determine the extended mnemonic. The number of these fields increases with the `typ` number. The comments explicitly mention "M-field values" and "offsets."

4. **Analyze `HandleExtndMnemonic`:** This function is the heart of the extended mnemonic logic. Key observations:
    * **Input:** It takes an `*Inst`. This implies the function operates on a parsed instruction.
    * **Data Structures:** It initializes slices of the `typNExtndMnics` structures. These slices seem to act as lookup tables.
    * **`switch` Statement:** The code uses a `switch` statement based on the `inst.Op.String()`. This suggests it handles different base instructions separately.
    * **Iteration and Comparison:** Within each `case`, the code iterates through the corresponding slice of `typNExtndMnics`. It compares fields of the `inst` (specifically `inst.Args` cast to `Mask`) with the `Value` fields in the lookup tables. The `Offset` fields determine which argument of the instruction to check.
    * **Mnemonic Replacement:** If a match is found, `newOpStr` is updated with the `ExtnOpStr`.
    * **Argument Removal:** The `removeArg` function is called. This suggests that the "M-field" values are part of the instruction encoding but are represented implicitly in the extended mnemonic, so they should be removed from the argument list when printing.
    * **Default Case:** If no extended mnemonic is found, the original `opString` is returned.

5. **Infer the Purpose of Extended Mnemonics:** Based on the structure and logic, extended mnemonics provide more readable and specific names for instructions based on the values of certain fields (the "M-fields"). For example, a generic "bc" (branch on condition) becomes "bo" (branch on overflow) when a specific bit in the condition code is set.

6. **Analyze `GNUSyntax`:** This function is simpler. It takes an `Inst` and a program counter (`pc`). It handles error cases (zero encoding or unknown opcode) and then calls `inst.String(pc)`. This strongly suggests that the `Inst` type has a method to generate the basic assembly string, and `HandleExtndMnemonic` modifies the *name* of the instruction before this.

7. **Analyze `removeArg`:** This is a utility function to remove an element from the `inst.Args` slice. This is necessary because the extended mnemonic implies the "M-field" value.

8. **Construct Examples:** Now, based on the understanding, we can create illustrative examples. Choose a few representative instructions from the lookup tables (e.g., `bc`, `bcr`, `vceq`). For each, construct a hypothetical `Inst` with the appropriate `Op` and `Args` to trigger a specific extended mnemonic. Show the before and after states of the instruction string and arguments.

9. **Identify Potential Pitfalls:** Think about how a user might interact with this code (likely indirectly through an assembler or disassembler). A key mistake could be manually trying to use the base mnemonic with the "M-field" arguments when an extended mnemonic exists. Another pitfall could be misunderstanding the mapping between the "M-field" values and the extended mnemonics.

10. **Address Specific Instructions:** Go back to the prompt and see if any specific instructions or argument handling were called out. For example, the "M-field" and "offset" are explicitly mentioned. Make sure the explanation clarifies how these concepts are implemented in the code.

11. **Refine and Organize:** Structure the answer logically. Start with a summary of the functionality, then delve into details of the key functions, provide examples, explain potential errors, and finally address any specific aspects mentioned in the prompt. Use clear language and code formatting.

This systematic approach of breaking down the code, analyzing its components, inferring its purpose, and then constructing examples and identifying potential issues leads to a comprehensive understanding and a well-structured answer.
这段Go语言代码是s390x架构汇编器的一部分，专门用于处理具有扩展助记符的指令，以便在GNU汇编语法中更清晰地表示这些指令。

**功能概览:**

1. **定义扩展助记符结构:**  代码定义了多种结构体 (`typ1ExtndMnics` 到 `typ5ExtndMnics`)，用于存储不同类型的扩展助记符信息。这些结构体包含了基本操作码字符串 (`BaseOpStr`)、用于匹配指令特定字段的值 (`ValueN`) 和偏移量 (`OffsetN`)，以及对应的扩展操作码字符串 (`ExtnOpStr`)。

2. **`HandleExtndMnemonic` 函数:** 这是核心函数，负责根据指令的内容（特别是操作码和特定的操作数字段的值）查找或构建扩展助记符。
   - 它维护了多个切片，每个切片都存储了特定指令的基本助记符及其对应的扩展助记符信息。
   - 它接收一个 `*Inst` 类型的参数，该参数包含了指令的所有信息，例如操作码、操作数等。
   - 它根据指令的基本操作码 (`inst.Op.String()`) 使用 `switch` 语句进行分发处理。
   - 在每个 `case` 中，它会遍历相应的扩展助记符信息切片。
   - 通过比较指令中特定操作数的值（通过 `inst.Args` 访问，并转换为 `Mask` 类型）与结构体中存储的 `Value`，以及操作数的索引与 `Offset`，来判断是否需要应用扩展助记符。
   - 如果找到匹配的扩展助记符，`HandleExtndMnemonic` 会更新指令的操作码字符串 (`newOpStr`)，并调用 `removeArg` 函数移除在扩展助记符中已经隐含的操作数。
   - 如果没有找到匹配的扩展助记符，则返回原始的操作码字符串。

3. **`GNUSyntax` 函数:**  此函数负责将 `Inst` 结构体转换为符合GNU汇编语法的字符串表示。它首先处理一些错误情况（例如，编码为0或未知指令），然后调用 `inst.String(pc)` 方法（`Inst` 结构体可能具有的打印自身的方法）来生成最终的汇编字符串。在调用 `inst.String` 之前，会先调用 `HandleExtndMnemonic` 来应用扩展助记符。

4. **`removeArg` 函数:**  这是一个辅助函数，用于从指令的参数列表中移除指定的参数。当应用扩展助记符时，某些操作数的值会被编码到助记符本身，因此需要从参数列表中移除。

**Go 语言功能实现推断和代码示例:**

这段代码是实现汇编器中指令格式化和输出的一部分。它利用 Go 语言的以下特性：

- **结构体 (Structs):** 用于组织和表示扩展助记符的信息。
- **切片 (Slices):** 用于存储同类型的扩展助记符结构体，方便遍历和查找。
- **函数 (Functions):** 用于封装不同的处理逻辑，例如查找扩展助记符、格式化输出和移除参数。
- **类型断言 (Type Assertion):**  将 `inst.Args` 中的元素断言为 `Mask` 或其他类型，以便进行比较。
- **`switch` 语句:** 用于根据不同的基本操作码执行不同的处理逻辑。

**代码示例 (假设的 `Inst` 结构体和 `Mask` 类型):**

```go
package s390xasm

import "fmt"

// 假设的 Mask 类型
type Mask uint8

// 假设的 Imm 类型
type Imm uint16

// 假设的 VReg 类型
type VReg uint8

// 假设的 Op 类型
type Op uint16

func (o Op) String() string {
	// ... 根据 Op 的值返回操作码字符串 ...
	opStrings := map[Op]string{
		0x0A: "bc",
		0xB204: "vceq",
		// ... 更多操作码 ...
	}
	if str, ok := opStrings[o]; ok {
		return str
	}
	return "unknown_op"
}

// 假设的 Inst 结构体
type Inst struct {
	Op  Op
	Args []interface{} // 操作数可以是寄存器、立即数、掩码等
	Enc uint32 // 指令编码
}

func (inst *Inst) String(pc uint64) string {
	// ... 根据 inst.Op 和 inst.Args 生成汇编字符串 ...
	argsStr := ""
	for i, arg := range inst.Args {
		argsStr += fmt.Sprintf("%v", arg)
		if i < len(inst.Args)-1 {
			argsStr += ", "
		}
	}
	return fmt.Sprintf("%s %s", inst.Op.String(), argsStr)
}

func main() {
	// 示例 1: BC 指令，M 字段值为 1，Offset 为 0
	inst1 := Inst{
		Op:  0x0A, // 代表 "bc"
		Args: []interface{}{Mask(1), 0x1000}, // 假设 Mask(1) 是 M 字段，0x1000 是目标地址
		Enc: 0x...,
	}
	gnuStr1 := GNUSyntax(inst1, 0)
	fmt.Println(gnuStr1) // 输出: bo 0x1000

	// 示例 2: VCEQ 指令，Value1 = 0, Value2 = 0, Offset1 = 3, Offset2 = 4 (假设的参数位置)
	inst2 := Inst{
		Op:  0xB204, // 代表 "vceq"
		Args: []interface{}{VReg(1), VReg(2), VReg(3), Mask(0), Mask(0), VReg(4)}, // 假设的参数顺序
		Enc: 0x...,
	}
	gnuStr2 := GNUSyntax(inst2, 0)
	fmt.Println(gnuStr2) // 输出: vceqb v1, v2, v4

}
```

**假设的输入与输出:**

- **输入 `HandleExtndMnemonic`:**
  ```go
  inst := &Inst{
      Op:  0x0A, // "bc"
      Args: []interface{}{Mask(1), 0x1000},
      Enc: 0x...,
  }
  ```
- **输出 `HandleExtndMnemonic`:** `"bo"` (并且 `inst.Args` 会变成 `[]interface{}{0x1000}`)

- **输入 `GNUSyntax`:**
  ```go
  inst := Inst{
      Op:  0x0A, // "bc"
      Args: []interface{}{0x1000}, // 经过 HandleExtndMnemonic 处理后的参数
      Enc: 0x...,
  }
  pc := uint64(0)
  ```
- **输出 `GNUSyntax`:** `"bo 0x1000"`

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是在汇编器内部使用的，负责将指令的内部表示转换为汇编字符串。命令行参数的处理通常发生在汇编器的更高层，用于指定输入文件、输出文件、目标架构等。

**使用者易犯错的点:**

1. **手动构造汇编指令时使用了基本助记符，但没有提供对应的 M 字段参数。**
   例如，使用者可能尝试写 `bc 1, 0x1000`，期望它等同于 `bo 0x1000`。但汇编器在处理 `bc` 时，如果没有检测到 `M` 字段值为 1，可能不会将其识别为有溢出分支。汇编器会根据 `HandleExtndMnemonic` 的逻辑来决定如何解释指令。

2. **不理解扩展助记符的含义，错误地使用了扩展助记符。**
   例如，使用者可能在不需要检查溢出的情况下使用了 `bo`，导致代码可读性下降，或者在某些汇编器实现中可能导致错误。

**总结:**

这段代码的核心功能是为 s390x 架构的汇编指令提供更友好的 GNU 汇编语法表示，通过使用扩展助记符来隐藏某些标志位或字段的细节，从而提高代码的可读性和可维护性。它通过定义一系列结构体和函数来实现这一目标，根据指令的特定字段值来查找或构建相应的扩展助记符，并在最终的汇编输出中替换基本助记符。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/arch/s390x/s390xasm/gnu.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2024 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package s390xasm

// Instructions with extended mnemonics fall under various categories.
// To handle each of them in one single function, various different
// structure types are defined as below. Corresponding instruction
// structures are created with the help of these base structures.
// Different instruction types are as below:

// Typ1 - Instructions having different base and extended mnemonic strings.
//
//	These instructions have single M-field value and single offset.
type typ1ExtndMnics struct {
	BaseOpStr string
	Value     uint8
	Offset    uint8
	ExtnOpStr string
}

// Typ2 - Instructions having couple of extra strings added to the base mnemonic string,
//
//	depending on the condition code evaluation.
//	These instructions have single M-field value and single offset.
type typ2ExtndMnics struct {
	Value     uint8
	Offset    uint8
	ExtnOpStr string
}

// Typ3 - Instructions having couple of extra strings added to the base mnemonic string,
//
//	depending on the condition code evaluation.
//	These instructions have two M-field values and two offsets.
type typ3ExtndMnics struct {
	Value1    uint8
	Value2    uint8
	Offset1   uint8
	Offset2   uint8
	ExtnOpStr string
}

// Typ4 - Instructions having different base and extended mnemonic strings.
//
//	These instructions have two M-field values and two offsets.
type typ4ExtndMnics struct {
	BaseOpStr string
	Value1    uint8
	Value2    uint8
	Offset1   uint8
	Offset2   uint8
	ExtnOpStr string
}

// Typ5 - Instructions having different base and extended mnemonic strings.
//
//	These instructions have three M-field values and three offsets.
type typ5ExtndMnics struct {
	BaseOpStr string
	Value1    uint8
	Value2    uint8
	Value3    uint8
	Offset1   uint8
	Offset2   uint8
	Offset3   uint8
	ExtnOpStr string
}

// "func Handleextndmnemonic" - This is the function where the extended mnemonic logic
// is implemented. This function defines various structures to keep a list of base
// instructions and their extended mnemonic strings. These structure will also have
// M-field values and offset values defined, based on their type.
// HandleExtndMnemonic takes "inst" structure as the input variable.
// Inst structure will have all the details related to an instruction. Based on the
// opcode base string, a switch-case statement is executed. In that, based on the
// M-field value and the offset value of that particular M-field, extended mnemonic
// string is either searched or constructed by adding couple of extra strings to the base
// opcode string from one of the structure defined below.
func HandleExtndMnemonic(inst *Inst) string {

	brnchInstrExtndMnics := []typ1ExtndMnics{
		//BIC - BRANCH INDIRECT ON CONDITION instruction
		typ1ExtndMnics{BaseOpStr: "bic", Value: 1, Offset: 0, ExtnOpStr: "bio"},
		typ1ExtndMnics{BaseOpStr: "bic", Value: 2, Offset: 0, ExtnOpStr: "bih"},
		typ1ExtndMnics{BaseOpStr: "bic", Value: 4, Offset: 0, ExtnOpStr: "bil"},
		typ1ExtndMnics{BaseOpStr: "bic", Value: 7, Offset: 0, ExtnOpStr: "bine"},
		typ1ExtndMnics{BaseOpStr: "bic", Value: 8, Offset: 0, ExtnOpStr: "bie"},
		typ1ExtndMnics{BaseOpStr: "bic", Value: 11, Offset: 0, ExtnOpStr: "binl"},
		typ1ExtndMnics{BaseOpStr: "bic", Value: 13, Offset: 0, ExtnOpStr: "binh"},
		typ1ExtndMnics{BaseOpStr: "bic", Value: 14, Offset: 0, ExtnOpStr: "bino"},
		typ1ExtndMnics{BaseOpStr: "bic", Value: 15, Offset: 0, ExtnOpStr: "bi"},

		//BCR - BRANCH ON CONDITION instruction
		typ1ExtndMnics{BaseOpStr: "bcr", Value: 0, Offset: 0, ExtnOpStr: "nopr"},
		typ1ExtndMnics{BaseOpStr: "bcr", Value: 1, Offset: 0, ExtnOpStr: "bor"},
		typ1ExtndMnics{BaseOpStr: "bcr", Value: 2, Offset: 0, ExtnOpStr: "bhr"},
		typ1ExtndMnics{BaseOpStr: "bcr", Value: 4, Offset: 0, ExtnOpStr: "blr"},
		typ1ExtndMnics{BaseOpStr: "bcr", Value: 7, Offset: 0, ExtnOpStr: "bner"},
		typ1ExtndMnics{BaseOpStr: "bcr", Value: 8, Offset: 0, ExtnOpStr: "ber"},
		typ1ExtndMnics{BaseOpStr: "bcr", Value: 11, Offset: 0, ExtnOpStr: "bnlr"},
		typ1ExtndMnics{BaseOpStr: "bcr", Value: 13, Offset: 0, ExtnOpStr: "bnhr"},
		typ1ExtndMnics{BaseOpStr: "bcr", Value: 14, Offset: 0, ExtnOpStr: "bnor"},
		typ1ExtndMnics{BaseOpStr: "bcr", Value: 15, Offset: 0, ExtnOpStr: "br"},

		//BC - BRANCH ON CONDITION instruction
		typ1ExtndMnics{BaseOpStr: "bc", Value: 0, Offset: 0, ExtnOpStr: "nopr"},
		typ1ExtndMnics{BaseOpStr: "bc", Value: 1, Offset: 0, ExtnOpStr: "bo"},
		typ1ExtndMnics{BaseOpStr: "bc", Value: 2, Offset: 0, ExtnOpStr: "bh"},
		typ1ExtndMnics{BaseOpStr: "bc", Value: 4, Offset: 0, ExtnOpStr: "bl"},
		typ1ExtndMnics{BaseOpStr: "bc", Value: 7, Offset: 0, ExtnOpStr: "bne"},
		typ1ExtndMnics{BaseOpStr: "bc", Value: 8, Offset: 0, ExtnOpStr: "be"},
		typ1ExtndMnics{BaseOpStr: "bc", Value: 11, Offset: 0, ExtnOpStr: "bnl"},
		typ1ExtndMnics{BaseOpStr: "bc", Value: 13, Offset: 0, ExtnOpStr: "bnh"},
		typ1ExtndMnics{BaseOpStr: "bc", Value: 14, Offset: 0, ExtnOpStr: "bno"},
		typ1ExtndMnics{BaseOpStr: "bc", Value: 15, Offset: 0, ExtnOpStr: "b"},

		//BRC - BRANCH RELATIVE ON CONDITION instruction
		typ1ExtndMnics{BaseOpStr: "brc", Value: 0, Offset: 0, ExtnOpStr: "jnop"},
		typ1ExtndMnics{BaseOpStr: "brc", Value: 1, Offset: 0, ExtnOpStr: "jo"},
		typ1ExtndMnics{BaseOpStr: "brc", Value: 2, Offset: 0, ExtnOpStr: "jh"},
		typ1ExtndMnics{BaseOpStr: "brc", Value: 4, Offset: 0, ExtnOpStr: "jl"},
		typ1ExtndMnics{BaseOpStr: "brc", Value: 7, Offset: 0, ExtnOpStr: "jne"},
		typ1ExtndMnics{BaseOpStr: "brc", Value: 8, Offset: 0, ExtnOpStr: "je"},
		typ1ExtndMnics{BaseOpStr: "brc", Value: 11, Offset: 0, ExtnOpStr: "jnl"},
		typ1ExtndMnics{BaseOpStr: "brc", Value: 13, Offset: 0, ExtnOpStr: "jnh"},
		typ1ExtndMnics{BaseOpStr: "brc", Value: 14, Offset: 0, ExtnOpStr: "jno"},
		typ1ExtndMnics{BaseOpStr: "brc", Value: 15, Offset: 0, ExtnOpStr: "j"},

		//BRCL - BRANCH RELATIVE ON CONDITION LONG instruction
		typ1ExtndMnics{BaseOpStr: "brcl", Value: 0, Offset: 0, ExtnOpStr: "jgnop"},
		typ1ExtndMnics{BaseOpStr: "brcl", Value: 1, Offset: 0, ExtnOpStr: "jgo"},
		typ1ExtndMnics{BaseOpStr: "brcl", Value: 2, Offset: 0, ExtnOpStr: "jgh"},
		typ1ExtndMnics{BaseOpStr: "brcl", Value: 4, Offset: 0, ExtnOpStr: "jgl"},
		typ1ExtndMnics{BaseOpStr: "brcl", Value: 7, Offset: 0, ExtnOpStr: "jgne"},
		typ1ExtndMnics{BaseOpStr: "brcl", Value: 8, Offset: 0, ExtnOpStr: "jge"},
		typ1ExtndMnics{BaseOpStr: "brcl", Value: 11, Offset: 0, ExtnOpStr: "jgnl"},
		typ1ExtndMnics{BaseOpStr: "brcl", Value: 13, Offset: 0, ExtnOpStr: "jgnh"},
		typ1ExtndMnics{BaseOpStr: "brcl", Value: 14, Offset: 0, ExtnOpStr: "jgno"},
		typ1ExtndMnics{BaseOpStr: "brcl", Value: 15, Offset: 0, ExtnOpStr: "jg"},
	}

	//Compare instructions
	cmpInstrExtndMnics := []typ2ExtndMnics{
		typ2ExtndMnics{Value: 2, Offset: 2, ExtnOpStr: "h"},
		typ2ExtndMnics{Value: 4, Offset: 2, ExtnOpStr: "l"},
		typ2ExtndMnics{Value: 6, Offset: 2, ExtnOpStr: "ne"},
		typ2ExtndMnics{Value: 8, Offset: 2, ExtnOpStr: "e"},
		typ2ExtndMnics{Value: 10, Offset: 2, ExtnOpStr: "nl"},
		typ2ExtndMnics{Value: 12, Offset: 2, ExtnOpStr: "nh"},
	}

	//Load and Store instructions
	ldSt_InstrExtndMnics := []typ2ExtndMnics{
		typ2ExtndMnics{Value: 1, Offset: 2, ExtnOpStr: "o"},
		typ2ExtndMnics{Value: 2, Offset: 2, ExtnOpStr: "h"},
		typ2ExtndMnics{Value: 3, Offset: 2, ExtnOpStr: "nle"},
		typ2ExtndMnics{Value: 4, Offset: 2, ExtnOpStr: "l"},
		typ2ExtndMnics{Value: 5, Offset: 2, ExtnOpStr: "nhe"},
		typ2ExtndMnics{Value: 6, Offset: 2, ExtnOpStr: "lh"},
		typ2ExtndMnics{Value: 7, Offset: 2, ExtnOpStr: "ne"},
		typ2ExtndMnics{Value: 8, Offset: 2, ExtnOpStr: "e"},
		typ2ExtndMnics{Value: 9, Offset: 2, ExtnOpStr: "nlh"},
		typ2ExtndMnics{Value: 10, Offset: 2, ExtnOpStr: "he"},
		typ2ExtndMnics{Value: 11, Offset: 2, ExtnOpStr: "nl"},
		typ2ExtndMnics{Value: 12, Offset: 2, ExtnOpStr: "le"},
		typ2ExtndMnics{Value: 13, Offset: 2, ExtnOpStr: "nh"},
		typ2ExtndMnics{Value: 14, Offset: 2, ExtnOpStr: "no"},
	}

	vecInstrExtndMnics := []typ2ExtndMnics{
		typ2ExtndMnics{Value: 0, Offset: 3, ExtnOpStr: "b"},
		typ2ExtndMnics{Value: 1, Offset: 3, ExtnOpStr: "h"},
		typ2ExtndMnics{Value: 2, Offset: 3, ExtnOpStr: "f"},
		typ2ExtndMnics{Value: 3, Offset: 3, ExtnOpStr: "g"},
		typ2ExtndMnics{Value: 4, Offset: 3, ExtnOpStr: "q"},
		typ2ExtndMnics{Value: 6, Offset: 3, ExtnOpStr: "lf"},
	}

	//VCEQ, VCH, VCHL
	vec2InstrExtndMnics := []typ3ExtndMnics{
		typ3ExtndMnics{Value1: 0, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "b"},
		typ3ExtndMnics{Value1: 1, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "h"},
		typ3ExtndMnics{Value1: 2, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "f"},
		typ3ExtndMnics{Value1: 3, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "g"},
		typ3ExtndMnics{Value1: 0, Value2: 1, Offset1: 3, Offset2: 4, ExtnOpStr: "bs"},
		typ3ExtndMnics{Value1: 1, Value2: 1, Offset1: 3, Offset2: 4, ExtnOpStr: "hs"},
		typ3ExtndMnics{Value1: 2, Value2: 1, Offset1: 3, Offset2: 4, ExtnOpStr: "fs"},
		typ3ExtndMnics{Value1: 3, Value2: 1, Offset1: 3, Offset2: 4, ExtnOpStr: "gs"},
	}

	//VFAE, VFEE, VFENE
	vec21InstrExtndMnics := []typ3ExtndMnics{
		typ3ExtndMnics{Value1: 0, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "b"},
		typ3ExtndMnics{Value1: 1, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "h"},
		typ3ExtndMnics{Value1: 2, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "f"},
		typ3ExtndMnics{Value1: 0, Value2: 1, Offset1: 3, Offset2: 4, ExtnOpStr: "bs"},
		typ3ExtndMnics{Value1: 1, Value2: 1, Offset1: 3, Offset2: 4, ExtnOpStr: "hs"},
		typ3ExtndMnics{Value1: 2, Value2: 1, Offset1: 3, Offset2: 4, ExtnOpStr: "fs"},
		typ3ExtndMnics{Value1: 0, Value2: 2, Offset1: 3, Offset2: 4, ExtnOpStr: "zb"},
		typ3ExtndMnics{Value1: 1, Value2: 2, Offset1: 3, Offset2: 4, ExtnOpStr: "zh"},
		typ3ExtndMnics{Value1: 2, Value2: 2, Offset1: 3, Offset2: 4, ExtnOpStr: "zf"},
		typ3ExtndMnics{Value1: 0, Value2: 3, Offset1: 3, Offset2: 4, ExtnOpStr: "zbs"},
		typ3ExtndMnics{Value1: 1, Value2: 3, Offset1: 3, Offset2: 4, ExtnOpStr: "zhs"},
		typ3ExtndMnics{Value1: 2, Value2: 3, Offset1: 3, Offset2: 4, ExtnOpStr: "zfs"},
	}

	vec3InstrExtndMnics := []typ3ExtndMnics{
		typ3ExtndMnics{Value1: 2, Value2: 0, Offset1: 2, Offset2: 3, ExtnOpStr: "sb"},
		typ3ExtndMnics{Value1: 3, Value2: 0, Offset1: 2, Offset2: 3, ExtnOpStr: "db"},
		typ3ExtndMnics{Value1: 4, Value2: 0, Offset1: 2, Offset2: 3, ExtnOpStr: "xb"},
	}

	vec4InstrExtndMnics := []typ4ExtndMnics{
		// VFA - VECTOR FP ADD
		typ4ExtndMnics{BaseOpStr: "vfa", Value1: 2, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfasb"},
		typ4ExtndMnics{BaseOpStr: "vfa", Value1: 3, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfadb"},
		typ4ExtndMnics{BaseOpStr: "vfa", Value1: 2, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfasb"},
		typ4ExtndMnics{BaseOpStr: "vfa", Value1: 3, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfadb"},
		typ4ExtndMnics{BaseOpStr: "vfa", Value1: 4, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfaxb"},

		// VFD - VECTOR FP DIVIDE
		typ4ExtndMnics{BaseOpStr: "vfd", Value1: 2, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfdsb"},
		typ4ExtndMnics{BaseOpStr: "vfd", Value1: 3, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfddb"},
		typ4ExtndMnics{BaseOpStr: "vfd", Value1: 2, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfdsb"},
		typ4ExtndMnics{BaseOpStr: "vfd", Value1: 3, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfddb"},
		typ4ExtndMnics{BaseOpStr: "vfd", Value1: 4, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfdxb"},

		// VFLL - VECTOR FP LOAD LENGTHENED
		typ4ExtndMnics{BaseOpStr: "vfll", Value1: 2, Value2: 0, Offset1: 2, Offset2: 3, ExtnOpStr: "vflfs"},
		typ4ExtndMnics{BaseOpStr: "vfll", Value1: 2, Value2: 8, Offset1: 2, Offset2: 3, ExtnOpStr: "wflls"},
		typ4ExtndMnics{BaseOpStr: "vfll", Value1: 3, Value2: 8, Offset1: 2, Offset2: 3, ExtnOpStr: "wflld"},

		// VFMAX - VECTOR FP MAXIMUM
		typ4ExtndMnics{BaseOpStr: "vfmax", Value1: 2, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfmaxsb"},
		typ4ExtndMnics{BaseOpStr: "vfmax", Value1: 3, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfmaxdb"},
		typ4ExtndMnics{BaseOpStr: "vfmax", Value1: 2, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfmaxsb"},
		typ4ExtndMnics{BaseOpStr: "vfmax", Value1: 3, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfmaxdb"},
		typ4ExtndMnics{BaseOpStr: "vfmax", Value1: 4, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfmaxxb"},

		// VFMIN - VECTOR FP MINIMUM
		typ4ExtndMnics{BaseOpStr: "vfmin", Value1: 2, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfminsb"},
		typ4ExtndMnics{BaseOpStr: "vfmin", Value1: 3, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfmindb"},
		typ4ExtndMnics{BaseOpStr: "vfmin", Value1: 2, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfminsb"},
		typ4ExtndMnics{BaseOpStr: "vfmin", Value1: 3, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfmindb"},
		typ4ExtndMnics{BaseOpStr: "vfmin", Value1: 4, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfminxb"},

		// VFM - VECTOR FP MULTIPLY
		typ4ExtndMnics{BaseOpStr: "vfm", Value1: 2, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfmsb"},
		typ4ExtndMnics{BaseOpStr: "vfm", Value1: 3, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfmdb"},
		typ4ExtndMnics{BaseOpStr: "vfm", Value1: 2, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfmsb"},
		typ4ExtndMnics{BaseOpStr: "vfm", Value1: 3, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfmdb"},
		typ4ExtndMnics{BaseOpStr: "vfm", Value1: 4, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfmxb"},

		// VFSQ - VECTOR FP SQUARE ROOT
		typ4ExtndMnics{BaseOpStr: "vfsq", Value1: 2, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfsqsb"},
		typ4ExtndMnics{BaseOpStr: "vfsq", Value1: 3, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfsqdb"},
		typ4ExtndMnics{BaseOpStr: "vfsq", Value1: 2, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfsqsb"},
		typ4ExtndMnics{BaseOpStr: "vfsq", Value1: 3, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfsqdb"},
		typ4ExtndMnics{BaseOpStr: "vfsq", Value1: 4, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfsqxb"},

		// VFS - VECTOR FP SUBTRACT
		typ4ExtndMnics{BaseOpStr: "vfs", Value1: 2, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfssb"},
		typ4ExtndMnics{BaseOpStr: "vfs", Value1: 3, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vfsdb"},
		typ4ExtndMnics{BaseOpStr: "vfs", Value1: 2, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfssb"},
		typ4ExtndMnics{BaseOpStr: "vfs", Value1: 3, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfsdb"},
		typ4ExtndMnics{BaseOpStr: "vfs", Value1: 4, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wfsxb"},

		// VFTCI - VECTOR FP TEST DATA CLASS IMMEDIATE
		typ4ExtndMnics{BaseOpStr: "vftci", Value1: 2, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vftcisb"},
		typ4ExtndMnics{BaseOpStr: "vftci", Value1: 3, Value2: 0, Offset1: 3, Offset2: 4, ExtnOpStr: "vftcidb"},
		typ4ExtndMnics{BaseOpStr: "vftci", Value1: 2, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wftcisb"},
		typ4ExtndMnics{BaseOpStr: "vftci", Value1: 3, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wftcidb"},
		typ4ExtndMnics{BaseOpStr: "vftci", Value1: 4, Value2: 8, Offset1: 3, Offset2: 4, ExtnOpStr: "wftcixb"},
	}

	vec6InstrExtndMnics := []typ5ExtndMnics{
		// VFCE - VECTOR FP COMPARE EQUAL
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 2, Value2: 0, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfcesb"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 2, Value2: 0, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfcesbs"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 3, Value2: 0, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfcedb"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 3, Value2: 0, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfcedbs"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 2, Value2: 8, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfcesb"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 2, Value2: 8, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfcesbs"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 3, Value2: 8, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfcedb"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 3, Value2: 8, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfcedbs"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 4, Value2: 8, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfcexb"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 4, Value2: 8, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfcexbs"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 2, Value2: 4, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkesb"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 2, Value2: 4, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkesbs"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 3, Value2: 4, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkedb"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 3, Value2: 4, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkedbs"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 2, Value2: 12, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkesb"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 2, Value2: 12, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkesbs"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 3, Value2: 12, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkedb"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 3, Value2: 12, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkedbs"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 4, Value2: 12, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkexb"},
		typ5ExtndMnics{BaseOpStr: "vfce", Value1: 4, Value2: 12, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkexbs"},

		// VFCH - VECTOR FP COMPARE HIGH
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 2, Value2: 0, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfchsb"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 2, Value2: 0, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfchsbs"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 3, Value2: 0, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfchdb"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 3, Value2: 0, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfchdbs"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 2, Value2: 8, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchsb"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 2, Value2: 8, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchsbs"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 3, Value2: 8, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchdb"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 3, Value2: 8, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchdbs"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 4, Value2: 8, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchxb"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 4, Value2: 8, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchxbs"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 2, Value2: 4, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkhsb"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 2, Value2: 4, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkhsbs"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 3, Value2: 4, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkhdb"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 3, Value2: 4, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkhdbs"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 2, Value2: 12, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhsb"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 2, Value2: 12, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhsbs"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 3, Value2: 12, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhdb"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 3, Value2: 12, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhdbs"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 4, Value2: 12, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhxb"},
		typ5ExtndMnics{BaseOpStr: "vfch", Value1: 4, Value2: 12, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhxbs"},

		// VFCHE - VECTOR FP COMPARE HIGH OR EQUAL
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 2, Value2: 0, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfchesb"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 2, Value2: 0, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfchesbs"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 3, Value2: 0, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfchedb"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 3, Value2: 0, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfchedbs"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 2, Value2: 8, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchesb"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 2, Value2: 8, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchesbs"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 3, Value2: 8, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchedb"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 3, Value2: 8, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchedbs"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 4, Value2: 8, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchexb"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 4, Value2: 8, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfchexbs"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 2, Value2: 4, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkhesb"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 2, Value2: 4, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkhesbs"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 3, Value2: 4, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkhedb"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 3, Value2: 4, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "vfkhedbs"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 2, Value2: 12, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhesb"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 2, Value2: 12, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhesbs"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 3, Value2: 12, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhedb"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 3, Value2: 12, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhedbs"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 4, Value2: 12, Value3: 0, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhexb"},
		typ5ExtndMnics{BaseOpStr: "vfche", Value1: 4, Value2: 12, Value3: 1, Offset1: 3, Offset2: 4, Offset3: 5, ExtnOpStr: "wfkhexbs"},

		// VFPSO - VECTOR FP PERFORM SIGN OPERATION
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 2, Value2: 0, Value3: 0, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "vflcsb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 2, Value2: 8, Value3: 0, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "wflcsb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 2, Value2: 0, Value3: 1, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "vflnsb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 2, Value2: 8, Value3: 1, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "wflnsb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 2, Value2: 0, Value3: 2, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "vflpsb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 2, Value2: 8, Value3: 2, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "wflpsb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 3, Value2: 0, Value3: 0, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "vflcdb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 3, Value2: 8, Value3: 0, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "wflcdb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 3, Value2: 0, Value3: 1, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "vflndb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 3, Value2: 8, Value3: 1, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "wflndb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 3, Value2: 0, Value3: 2, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "vflpdb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 3, Value2: 8, Value3: 2, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "wflpdb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 4, Value2: 8, Value3: 0, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "wflcxb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 4, Value2: 8, Value3: 1, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "wflnxb"},
		typ5ExtndMnics{BaseOpStr: "vfpso", Value1: 4, Value2: 8, Value3: 2, Offset1: 2, Offset2: 3, Offset3: 4, ExtnOpStr: "wflpxb"},
	}

	vec7InstrExtndMnics := []typ4ExtndMnics{
		// VFMA - VECTOR FP MULTIPLY AND ADD
		typ4ExtndMnics{BaseOpStr: "vfma", Value1: 0, Value2: 2, Offset1: 4, Offset2: 5, ExtnOpStr: "vfmasb"},
		typ4ExtndMnics{BaseOpStr: "vfma", Value1: 0, Value2: 3, Offset1: 4, Offset2: 5, ExtnOpStr: "vfmadb"},
		typ4ExtndMnics{BaseOpStr: "vfma", Value1: 8, Value2: 2, Offset1: 4, Offset2: 5, ExtnOpStr: "wfmasb"},
		typ4ExtndMnics{BaseOpStr: "vfma", Value1: 8, Value2: 3, Offset1: 4, Offset2: 5, ExtnOpStr: "wfmadb"},
		typ4ExtndMnics{BaseOpStr: "vfma", Value1: 8, Value2: 4, Offset1: 4, Offset2: 5, ExtnOpStr: "wfmaxb"},

		// VFMS - VECTOR FP MULTIPLY AND SUBTRACT
		typ4ExtndMnics{BaseOpStr: "vfms", Value1: 0, Value2: 2, Offset1: 4, Offset2: 5, ExtnOpStr: "vfmssb"},
		typ4ExtndMnics{BaseOpStr: "vfms", Value1: 0, Value2: 3, Offset1: 4, Offset2: 5, ExtnOpStr: "vfmsdb"},
		typ4ExtndMnics{BaseOpStr: "vfms", Value1: 8, Value2: 2, Offset1: 4, Offset2: 5, ExtnOpStr: "wfmssb"},
		typ4ExtndMnics{BaseOpStr: "vfms", Value1: 8, Value2: 3, Offset1: 4, Offset2: 5, ExtnOpStr: "wfmsdb"},
		typ4ExtndMnics{BaseOpStr: "vfms", Value1: 8, Value2: 4, Offset1: 4, Offset2: 5, ExtnOpStr: "wfmsxb"},

		// VFNMA - VECTOR FP NEGATIVE MULTIPLY AND ADD
		typ4ExtndMnics{BaseOpStr: "vfnma", Value1: 0, Value2: 2, Offset1: 4, Offset2: 5, ExtnOpStr: "vfnmasb"},
		typ4ExtndMnics{BaseOpStr: "vfnma", Value1: 0, Value2: 3, Offset1: 4, Offset2: 5, ExtnOpStr: "vfnmadb"},
		typ4ExtndMnics{BaseOpStr: "vfnma", Value1: 8, Value2: 2, Offset1: 4, Offset2: 5, ExtnOpStr: "wfnmasb"},
		typ4ExtndMnics{BaseOpStr: "vfnma", Value1: 8, Value2: 3, Offset1: 4, Offset2: 5, ExtnOpStr: "wfnmadb"},
		typ4ExtndMnics{BaseOpStr: "vfnma", Value1: 8, Value2: 4, Offset1: 4, Offset2: 5, ExtnOpStr: "wfnmaxb"},

		// VFNMS - VECTOR FP NEGATIVE MULTIPLY AND SUBTRACT
		typ4ExtndMnics{BaseOpStr: "vfnms", Value1: 0, Value2: 2, Offset1: 4, Offset2: 5, ExtnOpStr: "vfnmssb"},
		typ4ExtndMnics{BaseOpStr: "vfnms", Value1: 0, Value2: 3, Offset1: 4, Offset2: 5, ExtnOpStr: "vfnmsdb"},
		typ4ExtndMnics{BaseOpStr: "vfnms", Value1: 8, Value2: 2, Offset1: 4, Offset2: 5, ExtnOpStr: "wfnmssb"},
		typ4ExtndMnics{BaseOpStr: "vfnms", Value1: 8, Value2: 3, Offset1: 4, Offset2: 5, ExtnOpStr: "wfnmsdb"},
		typ4ExtndMnics{BaseOpStr: "vfnms", Value1: 8, Value2: 4, Offset1: 4, Offset2: 5, ExtnOpStr: "wfnmsxb"},
	}

	opString := inst.Op.String()
	newOpStr := opString

	if inst.Enc == 0 {
		return ".long 0x0"
	} else if inst.Op == 0 {
		return "error: unknown instruction"
	}

	switch opString {
	// Case to handle all "branch" instructions with one M-field operand
	case "bic", "bcr", "bc", "brc", "brcl":

		for i := 0; i < len(brnchInstrExtndMnics); i++ {
			if opString == brnchInstrExtndMnics[i].BaseOpStr &&
				uint8(inst.Args[brnchInstrExtndMnics[i].Offset].(Mask)) == brnchInstrExtndMnics[i].Value {
				newOpStr = brnchInstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(brnchInstrExtndMnics[i].Offset))
				break
			}
		}

	// Case to handle all "compare" instructions with one M-field operand
	case "crb", "cgrb", "crj", "cgrj", "crt", "cgrt", "cib", "cgib", "cij", "cgij", "cit", "cgit", "clrb", "clgrb",
		"clrj", "clgrj", "clrt", "clgrt", "clt", "clgt", "clib", "clgib", "clij", "clgij", "clfit", "clgit":

		for i := 0; i < len(cmpInstrExtndMnics); i++ {
			//For CLT and CLGT instructions, M-value is the second operand.
			//Hence, set the offset to "1"
			if opString == "clt" || opString == "clgt" {
				cmpInstrExtndMnics[i].Offset = 1
			}

			if uint8(inst.Args[cmpInstrExtndMnics[i].Offset].(Mask)) == cmpInstrExtndMnics[i].Value {
				newOpStr = opString + cmpInstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(cmpInstrExtndMnics[i].Offset))
				break
			}
		}

	// Case to handle all "load" and "store" instructions with one M-field operand
	case "lochhi", "lochi", "locghi", "locfhr", "locfh", "locr", "locgr", "loc",
		"locg", "selr", "selgr", "selfhr", "stocfh", "stoc", "stocg":

		for i := 0; i < len(ldSt_InstrExtndMnics); i++ {

			//For LOCFH, LOC, LOCG, SELR, SELGR, SELFHR, STOCFH, STOC, STOCG instructions,
			//M-value is the forth operand. Hence, set the offset to "3"
			if opString == "locfh" || opString == "loc" || opString == "locg" || opString == "selr" || opString == "selgr" ||
				opString == "selfhr" || opString == "stocfh" || opString == "stoc" || opString == "stocg" {
				ldSt_InstrExtndMnics[i].Offset = 3
			}

			if uint8(inst.Args[ldSt_InstrExtndMnics[i].Offset].(Mask)) == ldSt_InstrExtndMnics[i].Value {
				newOpStr = opString + ldSt_InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(ldSt_InstrExtndMnics[i].Offset))
				break
			}
		}

	// Case to handle all "vector" instructions with one M-field operand
	case "vavg", "vavgl", "verllv", "veslv", "vesrav", "vesrlv", "vgfm", "vgm", "vmx", "vmxl", "vmrh", "vmrl", "vmn", "vmnl", "vrep",
		"vclz", "vctz", "vec", "vecl", "vlc", "vlp", "vpopct", "vrepi", "verim", "verll", "vesl", "vesra", "vesrl", "vgfma", "vlrep",
		"vlgv", "vlvg", "vlbrrep", "vler", "vlbr", "vstbr", "vster", "vpk", "vme", "vmh", "vmle", "vmlh", "vmlo", "vml", "vmo", "vmae",
		"vmale", "vmalo", "vmal", "vmah", "vmalh", "vmao", "vmph", "vmplh", "vupl", "vupll", "vscbi", "vs", "vsum", "vsumg", "vsumq", "va", "vacc":

		switch opString {

		case "vavg", "vavgl", "verllv", "veslv", "vesrav", "vesrlv", "vgfm", "vgm", "vmx", "vmxl", "vmrh", "vmrl", "vmn", "vmnl", "vrep":
			//M-field is 3rd arg for all these instructions. Hence, set the offset to "2"
			for i := 0; i < len(vecInstrExtndMnics)-2; i++ { // 0,1,2,3
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset))
					break
				}
			}

		case "vclz", "vctz", "vec", "vecl", "vlc", "vlp", "vpopct", "vrepi":
			for i := 0; i < len(vecInstrExtndMnics)-2; i++ { //0,1,2,3
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset-1].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset-1))
					break
				}
			}

		case "verim", "verll", "vesl", "vesra", "vesrl", "vgfma", "vlrep":
			for i := 0; i < len(vecInstrExtndMnics)-2; i++ { //0,1,2,3
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset+1].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset+1))
					break
				}
			}

		case "vlgv", "vlvg":
			for i := 0; i < len(vecInstrExtndMnics)-2; i++ {
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset+1].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset+1))
					break
				}
			}

		case "vlbrrep", "vler", "vster":
			for i := 1; i < len(vecInstrExtndMnics)-2; i++ {
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset+1].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset+1))
					break
				}
			}

		case "vpk":
			for i := 1; i < len(vecInstrExtndMnics)-2; i++ {
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset))
					break
				}
			}

		case "vlbr", "vstbr":
			for i := 1; i < len(vecInstrExtndMnics)-1; i++ {
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset+1].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset+1))
					break
				}
			}
		case "vme", "vmh", "vmle", "vmlh", "vmlo", "vmo":
			for i := 0; i < len(vecInstrExtndMnics)-3; i++ { //0,1,2
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset))
					break
				}
			}

		case "vml":
			for i := 0; i < len(vecInstrExtndMnics)-3; i++ { //0,1,2
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset].(Mask)) == vecInstrExtndMnics[i].Value {
					if uint8(inst.Args[vecInstrExtndMnics[i].Offset].(Mask)) == 1 {
						newOpStr = opString + string("hw")
					} else {
						newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					}
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset))
					break
				}
			}

		case "vmae", "vmale", "vmalo", "vmal", "vmah", "vmalh", "vmao":
			for i := 0; i < len(vecInstrExtndMnics)-3; i++ { //0,1,2
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset+1].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset+1))
					break
				}
			}

		case "vmph", "vmplh", "vupl", "vupll": //0,1,2
			for i := 0; i < len(vecInstrExtndMnics)-3; i++ {
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset-1].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset-1))
					break
				}
			}

		case "vscbi", "vs", "va", "vacc": // 0,1,2,3,4
			for i := 0; i < len(vecInstrExtndMnics)-1; i++ {
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset))
					break
				}
			}
		case "vsum", "vsumg", "vsumq":
			var off int
			switch opString {
			case "vsum":
				off = 0
			case "vsumg":
				off = 1
			case "vsumq":
				off = 2

			}
			for i := off; i < len(vecInstrExtndMnics)-4+off; i++ {
				if uint8(inst.Args[vecInstrExtndMnics[i].Offset].(Mask)) == vecInstrExtndMnics[i].Value {
					newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
					removeArg(inst, int8(vecInstrExtndMnics[i].Offset))
					break
				}
			}
		}

	case "vllez":
		for i := 0; i < len(vecInstrExtndMnics); i++ {
			if i == 4 {
				continue
			}
			if uint8(inst.Args[vecInstrExtndMnics[i].Offset+1].(Mask)) == vecInstrExtndMnics[i].Value {
				newOpStr = opString + vecInstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vecInstrExtndMnics[i].Offset+1))
				break
			}
		}

	case "vgbm":
		if uint16(inst.Args[1].(Imm)) == uint16(0) {
			newOpStr = "vzeo"
			removeArg(inst, int8(1))
		} else if uint16(inst.Args[1].(Imm)) == uint16(0xFFFF) {
			newOpStr = "vone"
			removeArg(inst, int8(1))
		}
	case "vno":
		if uint8(inst.Args[1].(VReg)) == uint8(inst.Args[2].(VReg)) { //Bitwise Not instruction(VNOT)  if V2 equal to v3
			newOpStr = opString + "t"
			removeArg(inst, int8(2))
		}

	case "vmsl":
		if uint8(inst.Args[4].(Mask)) == uint8(3) {
			newOpStr = opString + "g"
			removeArg(inst, int8(4))
		}

	case "vflr":
		if uint8(inst.Args[2].(Mask)) == uint8(3) && ((inst.Args[3].(Mask)>>3)&0x1 == 0x1) {
			inst.Args[3] = (inst.Args[3].(Mask) ^ 0x8)
			newOpStr = "wflrd"
			removeArg(inst, int8(2))
		} else if uint8(inst.Args[2].(Mask)) == uint8(4) && ((inst.Args[3].(Mask)>>3)&0x1 == 0x1) {
			inst.Args[3] = (inst.Args[3].(Mask) ^ 0x8)
			newOpStr = "wflrx"
			removeArg(inst, int8(2))
		} else if uint8(inst.Args[2].(Mask)) == uint8(3) {
			newOpStr = "vflrd"
			removeArg(inst, int8(2))
		}

	case "vllebrz":
		if uint8(inst.Args[4].(Mask)) == uint8(1) {
			newOpStr = opString + "h"
			removeArg(inst, int8(4))
		} else if uint8(inst.Args[4].(Mask)) == uint8(2) {
			newOpStr = opString + "f"
			removeArg(inst, int8(4))
		} else if uint8(inst.Args[4].(Mask)) == uint8(3) {
			newOpStr = "ldrv"
			removeArg(inst, int8(4))
		} else if uint8(inst.Args[4].(Mask)) == uint8(6) {
			newOpStr = "lerv"
			removeArg(inst, int8(4))
		}

	case "vschp":
		if uint8(inst.Args[3].(Mask)) == uint8(2) {
			newOpStr = "vschsp"
			removeArg(inst, int8(3))
		} else if uint8(inst.Args[3].(Mask)) == uint8(3) {
			newOpStr = "vschdp"
			removeArg(inst, int8(3))
		} else if uint8(inst.Args[3].(Mask)) == uint8(4) {
			newOpStr = "vschxp"
			removeArg(inst, int8(3))
		}

	case "vsbcbi", "vsbi":
		if uint8(inst.Args[4].(Mask)) == uint8(4) {
			newOpStr = opString + vecInstrExtndMnics[4].ExtnOpStr
			removeArg(inst, int8(4))
		}

	case "vac", "vaccc":
		if uint8(inst.Args[4].(Mask)) == uint8(4) {
			newOpStr = opString + vecInstrExtndMnics[4].ExtnOpStr
			removeArg(inst, int8(4))
		}

	case "vceq", "vch", "vchl":
		for i := 0; i < len(vec2InstrExtndMnics)-6; i++ {
			if uint8(inst.Args[vec2InstrExtndMnics[i].Offset1].(Mask)) == vec2InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec2InstrExtndMnics[i].Offset2].(Mask)) == vec2InstrExtndMnics[i].Value2 {
				newOpStr = opString + vec2InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec2InstrExtndMnics[i].Offset1))
				removeArg(inst, int8(vec2InstrExtndMnics[i].Offset2-1))
				break
			}
		}

	case "vpks", "vpkls":
		for i := 1; i < len(vec2InstrExtndMnics)-6; i++ {
			if i == 4 {
				continue
			}
			if uint8(inst.Args[vec2InstrExtndMnics[i].Offset1].(Mask)) == vec2InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec2InstrExtndMnics[i].Offset2].(Mask)) == vec2InstrExtndMnics[i].Value2 {
				newOpStr = opString + vec2InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec2InstrExtndMnics[i].Offset1))
				removeArg(inst, int8(vec2InstrExtndMnics[i].Offset2-1))
				break
			}
		}
	case "vfee", "vfene":
		var check bool
		for i := 0; i < len(vec21InstrExtndMnics); i++ {
			if uint8(inst.Args[vec21InstrExtndMnics[i].Offset1].(Mask)) == vec21InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec21InstrExtndMnics[i].Offset2].(Mask)) == vec21InstrExtndMnics[i].Value2 {
				newOpStr = opString + vec21InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset1))
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset2-1))
				check = true
				break
			}
		}
		if !check {
			if uint8(inst.Args[3].(Mask)) == 0 && (uint8(inst.Args[4].(Mask)) != uint8(0)) {
				newOpStr = opString + vec21InstrExtndMnics[0].ExtnOpStr
				removeArg(inst, int8(vec21InstrExtndMnics[0].Offset1))
			} else if uint8(inst.Args[3].(Mask)) == 1 && (uint8(inst.Args[4].(Mask)) != uint8(0)) {
				newOpStr = opString + vec21InstrExtndMnics[1].ExtnOpStr
				removeArg(inst, int8(vec21InstrExtndMnics[1].Offset1))
			} else if uint8(inst.Args[3].(Mask)) == 2 && (uint8(inst.Args[4].(Mask)) != uint8(0)) {
				newOpStr = opString + vec21InstrExtndMnics[2].ExtnOpStr
				removeArg(inst, int8(vec21InstrExtndMnics[2].Offset1))
			} else if uint8(inst.Args[4].(Mask)) == 0 {
				removeArg(inst, int8(vec21InstrExtndMnics[2].Offset2))
			}
		}

	case "vfae", "vstrc":
		off := uint8(0)
		var check bool
		if opString == "vstrc" {
			off = uint8(1)
		}
		for i := 0; i < len(vec21InstrExtndMnics)-9; i++ {
			if uint8(inst.Args[vec21InstrExtndMnics[i].Offset1+off].(Mask)) == vec21InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec21InstrExtndMnics[i].Offset2+off].(Mask)) == vec21InstrExtndMnics[i].Value2 {
				newOpStr = opString + vec21InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset1+off))
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset2+off-1))
				check = true
				break
			}
		}

		for i := 0; !(check) && (i < len(vec21InstrExtndMnics)-9); i++ {
			if uint8(inst.Args[vec21InstrExtndMnics[i].Offset1+off].(Mask)) == vec21InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec21InstrExtndMnics[i].Offset2+off].(Mask)) == vec21InstrExtndMnics[i].Value2 {
				newOpStr = opString + vec21InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset1+off))
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset2+off-1))
				check = true
				break
			}
		}
		//for i := 3; !(check) && (i < len(vec21InstrExtndMnics)); i++ {
		for i := len(vec21InstrExtndMnics) - 1; !(check) && (i > 2); i-- {
			if uint8(inst.Args[vec21InstrExtndMnics[i].Offset1+off].(Mask)) == vec21InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec21InstrExtndMnics[i].Offset2+off].(Mask))&(vec21InstrExtndMnics[i].Value2) == vec21InstrExtndMnics[i].Value2 {
				x := uint8(inst.Args[vec21InstrExtndMnics[i].Offset2+off].(Mask)) ^ (vec21InstrExtndMnics[i].Value2)
				newOpStr = opString + vec21InstrExtndMnics[i].ExtnOpStr
				if x != 0 {
					inst.Args[vec21InstrExtndMnics[i].Offset2+off] = Mask(x)
					removeArg(inst, int8(vec21InstrExtndMnics[i].Offset1+off))
					check = true
					break
				} else {
					removeArg(inst, int8(vec21InstrExtndMnics[i].Offset1+off))
					removeArg(inst, int8(vec21InstrExtndMnics[i].Offset2+off-1))
					check = true
					break
				}
			}
		}
		if !check && inst.Args[4+off].(Mask) == Mask(0) {
			removeArg(inst, int8(4+off))
			break
		}

	case "vstrs":
		var check bool
		for i := 0; i < len(vec21InstrExtndMnics)-3; i++ {
			if uint8(inst.Args[vec21InstrExtndMnics[i].Offset1+1].(Mask)) == vec21InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec21InstrExtndMnics[i].Offset2+1].(Mask)) == vec21InstrExtndMnics[i].Value2 {
				newOpStr = opString + vec21InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset1+1))
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset2))
				check = true
				break
			}
			if i == 2 {
				i = i + 3
			}
		}

		for i := 0; !(check) && (i < len(vec21InstrExtndMnics)-9); i++ {
			if uint8(inst.Args[vec21InstrExtndMnics[i].Offset1+1].(Mask)) == vec21InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec21InstrExtndMnics[i].Offset2+1].(Mask)) != 0 {
				newOpStr = opString + vec21InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset1+1))
				break
			}
		}

	case "vistr":
		var check bool
		for i := 0; i < len(vec21InstrExtndMnics)-6; i++ {
			if uint8(inst.Args[vec21InstrExtndMnics[i].Offset1-1].(Mask)) == vec21InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec21InstrExtndMnics[i].Offset2-1].(Mask)) == vec21InstrExtndMnics[i].Value2 {
				newOpStr = opString + vec21InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset1-1))
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset2-2))
				check = true
				break
			}
		}

		for i := 0; !(check) && (i < len(vec21InstrExtndMnics)-9); i++ {
			if uint8(inst.Args[vec21InstrExtndMnics[i].Offset1-1].(Mask)) == vec21InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec21InstrExtndMnics[i].Offset2-1].(Mask)) != 0 {
				newOpStr = opString + vec21InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec21InstrExtndMnics[i].Offset1-1))
				break
			}
		}

		if uint8(inst.Args[3].(Mask)) == 0 {
			removeArg(inst, int8(3))
			break
		}

	case "vcfps":
		if inst.Args[2].(Mask) == Mask(2) && ((inst.Args[3].(Mask)>>3)&(0x1) == 1) {
			inst.Args[3] = Mask((inst.Args[3].(Mask)) ^ (0x8))
			newOpStr = "wcefb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(3) && ((inst.Args[3].(Mask)>>3)&(0x1) == 1) {
			inst.Args[3] = Mask((inst.Args[3].(Mask)) ^ (0x8))
			newOpStr = "wcdgb"
			removeArg(inst, int8(2))
			break
		} else if uint8(inst.Args[2].(Mask)) == uint8(2) {
			newOpStr = "vcefb"
			removeArg(inst, int8(2))
			break
		} else if uint8(inst.Args[2].(Mask)) == uint8(3) {
			newOpStr = "vcdgb"
			removeArg(inst, int8(2))
			break
		}

	case "vcfpl":
		if inst.Args[2].(Mask) == Mask(2) && ((inst.Args[3].(Mask)>>3)&(0x1) == 1) {
			inst.Args[3] = Mask((inst.Args[3].(Mask)) ^ (0x8))
			newOpStr = "wcelfb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(3) && ((inst.Args[3].(Mask)>>3)&(0x1) == 1) {
			inst.Args[3] = Mask((inst.Args[3].(Mask)) ^ (0x8))
			newOpStr = "wcdlgb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(2) {
			newOpStr = "vcelfb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(3) {
			newOpStr = "vcdlgb"
			removeArg(inst, int8(2))
			break
		}

	case "vcsfp":
		if inst.Args[2].(Mask) == Mask(2) && ((inst.Args[3].(Mask)>>3)&(0x1) == 1) {
			inst.Args[3] = Mask((inst.Args[3].(Mask)) ^ (0x8))
			newOpStr = "wcfeb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(3) && ((inst.Args[3].(Mask)>>3)&(0x1) == 1) {
			inst.Args[3] = Mask((inst.Args[3].(Mask)) ^ (0x8))
			newOpStr = "wcgdb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(2) {
			newOpStr = "vcfeb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(3) {
			newOpStr = "vcgdb"
			removeArg(inst, int8(2))
			break
		}

	case "vclfp":
		if inst.Args[2].(Mask) == Mask(2) && ((inst.Args[3].(Mask)>>3)&(0x1) == 1) {
			inst.Args[3] = Mask((inst.Args[3].(Mask)) ^ (0x8))
			newOpStr = "wclfeb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(3) && ((inst.Args[3].(Mask)>>3)&(0x1) == 1) {
			inst.Args[3] = Mask((inst.Args[3].(Mask)) ^ (0x8))
			newOpStr = "wclgdb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(2) {
			newOpStr = "vclfeb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(3) {
			newOpStr = "vclgdb"
			removeArg(inst, int8(2))
			break
		}

	case "vfi":
		if inst.Args[2].(Mask) == Mask(2) && ((inst.Args[3].(Mask)>>3)&(0x1) == 1) {
			newOpStr = "wfisb"
			removeArg(inst, int8(2))
			inst.Args[2] = Mask((inst.Args[2].(Mask)) ^ (0x8))
			break
		} else if inst.Args[2].(Mask) == Mask(3) && ((inst.Args[3].(Mask)>>3)&(0x3) == 1) {
			newOpStr = "wfidb"
			removeArg(inst, int8(2))
			inst.Args[2] = Mask((inst.Args[2].(Mask)) ^ (0x8))
			break
		} else if inst.Args[2].(Mask) == Mask(4) && ((inst.Args[3].(Mask)>>3)&(0x1) == 1) {
			newOpStr = "wfixb"
			removeArg(inst, int8(2))
			inst.Args[2] = Mask((inst.Args[2].(Mask)) ^ (0x8))
			break
		} else if inst.Args[2].(Mask) == Mask(2) {
			newOpStr = "vfisb"
			removeArg(inst, int8(2))
			break
		} else if inst.Args[2].(Mask) == Mask(3) {
			newOpStr = "vfidb"
			removeArg(inst, int8(2))
			break
		}

	// Case to handle few vector instructions with 2 M-field operands
	case "vfa", "vfd", "vfll", "vfmax", "vfmin", "vfm":
		for i := 0; i < len(vec4InstrExtndMnics); i++ {
			if opString == vec4InstrExtndMnics[i].BaseOpStr &&
				uint8(inst.Args[vec4InstrExtndMnics[i].Offset1].(Mask)) == vec4InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec4InstrExtndMnics[i].Offset2].(Mask)) == vec4InstrExtndMnics[i].Value2 {
				newOpStr = vec4InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec4InstrExtndMnics[i].Offset1))
				removeArg(inst, int8(vec4InstrExtndMnics[i].Offset2-1))
				break
			}
		}

	// Case to handle few special "vector" instructions with 2 M-field operands
	case "wfc", "wfk":
		for i := 0; i < len(vec3InstrExtndMnics); i++ {
			if uint8(inst.Args[vec3InstrExtndMnics[i].Offset1].(Mask)) == vec3InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec3InstrExtndMnics[i].Offset2].(Mask)) == vec3InstrExtndMnics[i].Value2 {
				newOpStr = opString + vec3InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec3InstrExtndMnics[i].Offset1))
				removeArg(inst, int8(vec3InstrExtndMnics[i].Offset2-1))
				break
			}
		}

	// Case to handle few vector instructions with 2 M-field operands
	case "vfma", "vfms", "vfnma", "vfnms":
		for i := 0; i < len(vec7InstrExtndMnics); i++ {
			if opString == vec7InstrExtndMnics[i].BaseOpStr &&
				uint8(inst.Args[vec7InstrExtndMnics[i].Offset1].(Mask)) == vec7InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec7InstrExtndMnics[i].Offset2].(Mask)) == vec7InstrExtndMnics[i].Value2 {
				newOpStr = vec7InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec7InstrExtndMnics[i].Offset1))
				removeArg(inst, int8(vec7InstrExtndMnics[i].Offset2-1))
				break
			}
		}

	// List of instructions with 3 M-field operands.
	case "vfce", "vfch", "vfche", "vfpso":
		for i := 0; i < len(vec6InstrExtndMnics); i++ {
			if opString == vec6InstrExtndMnics[i].BaseOpStr &&
				uint8(inst.Args[vec6InstrExtndMnics[i].Offset1].(Mask)) == vec6InstrExtndMnics[i].Value1 &&
				uint8(inst.Args[vec6InstrExtndMnics[i].Offset2].(Mask)) == vec6InstrExtndMnics[i].Value2 &&
				uint8(inst.Args[vec6InstrExtndMnics[i].Offset3].(Mask)) == vec6InstrExtndMnics[i].Value3 {
				newOpStr = vec6InstrExtndMnics[i].ExtnOpStr
				removeArg(inst, int8(vec6InstrExtndMnics[i].Offset1))
				removeArg(inst, int8(vec6InstrExtndMnics[i].Offset2-1))
				removeArg(inst, int8(vec6InstrExtndMnics[i].Offset3-2))
				break
			}
		}

	default:
		return opString
	}
	return newOpStr
}

// This is the function that is called to print the disassembled instruction
// in the GNU (AT&T) syntax form.
func GNUSyntax(inst Inst, pc uint64) string {
	if inst.Enc == 0 {
		return ".long 0x0"
	} else if inst.Op == 0 {
		return "error: unknown instruction"
	}
	return inst.String(pc)
}

// removeArg removes the arg in inst.Args[index].
func removeArg(inst *Inst, index int8) {
	for i := int(index); i < len(inst.Args); i++ {
		if i+1 < len(inst.Args) {
			inst.Args[i] = inst.Args[i+1]
		} else {
			inst.Args[i] = nil
		}
	}
}

"""



```