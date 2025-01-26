Response:
Let's break down the thought process for answering this multi-part question about the provided Go code snippet.

**1. Understanding the Core Task:**

The fundamental goal is to analyze a specific piece of Go code from `go/src/debug/elf/elf.go` and describe its functionality. The request specifically mentions it's "part 3 of 5," implying the broader context is likely about parsing and understanding ELF (Executable and Linkable Format) files.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to read through the code snippet. Key observations jump out immediately:

* **Type Definitions:**  We see definitions for `R_AARCH64`, `R_ALPHA`, `R_ARM`, `R_386`, `R_MIPS`, and `R_LARCH`. These look like enumeration-like types (using `int` as the underlying type with associated constants).
* **Constant Blocks:** Each type definition is followed by a `const` block defining specific values for that type. The naming convention (`R_ARCH_SOMETHING`) is very consistent.
* **String Representation:**  Each type has `String()` and `GoString()` methods. These methods call a function `stringName`. This strongly suggests a mechanism for converting the integer values of these relocation types into human-readable strings.
* **`stringName` Function (Implicit):** While not in the snippet, the repeated use of `stringName` tells us it's a central function. We can infer its signature (something like `func stringName(val uint32, names []intName, goSyntax bool) string`) and purpose.
* **`intName` Type (Implicit):** The `stringName` function takes a `[]intName` as an argument. Looking at how the constant data is organized, we can infer that `intName` is likely a struct like `struct { i int; name string }`.

**3. Deducing the Functionality:**

Based on the above observations, the primary function of this code snippet is to define and manage *relocation types* for different CPU architectures (AArch64, Alpha, ARM, x86, MIPS, LoongArch).

* **Relocation Types:** These types represent different kinds of adjustments that need to be made to code or data when linking and loading an executable or shared library. The specific constants (`R_AARCH64_ABS64`, `R_ARM_REL32`, etc.) likely correspond to defined relocation types within the ELF standard for each architecture.
* **String Conversion:** The `String()` method provides a user-friendly string representation of these relocation types, useful for debugging and logging. The `GoString()` method likely provides a Go-specific string representation (perhaps including the type name).

**4. Inferring the Broader Go Feature:**

Knowing this code is about relocation types within ELF files, the broader Go feature it implements is clearly **ELF file parsing and analysis**. The `debug/elf` package is dedicated to this purpose.

**5. Providing Go Code Examples:**

To illustrate, we need to show how these relocation types would be used in a Go program. This involves:

* **Opening an ELF file:**  The `os.Open()` function is the standard way to open files.
* **Using the `debug/elf` package:** The `elf.NewFile()` function is the logical choice to parse the ELF file.
* **Accessing relocation information:**  ELF files contain sections related to relocations. We would need to iterate through these sections and access the relocation entries. The `elf.File` struct would likely have methods or fields to access these. *(Initially, I might not know the exact methods, but I'd make an educated guess, like `f.Sections`, and then refine it based on documentation or further code inspection.)*
* **Accessing the relocation type:**  Each relocation entry would have a `Type` field, which would be one of the `R_ARCH` types defined in the snippet. We can then use the `String()` method to get its textual representation.

**6. Considering Command-Line Arguments:**

Since this code snippet focuses on data structures and type definitions, it's unlikely to directly handle command-line arguments. The broader `debug/elf` package might have tools that use these types and accept command-line arguments (like `go tool objdump`), but this specific snippet doesn't.

**7. Identifying Potential Pitfalls:**

The most likely error users might make is **incorrectly interpreting the meaning of specific relocation types**. These types are architecture-specific and have precise definitions within the ELF standard. A user might assume a relocation does one thing when it does something subtly different. An example illustrating the difference between `R_386_PC32` and `R_386_32` would be helpful here.

**8. Structuring the Answer:**

Finally, the answer needs to be structured clearly, addressing each part of the prompt:

* **功能列举:**  List the core functionalities identified (defining relocation types, string conversion).
* **Go语言功能推断和代码示例:** State the inferred Go feature (ELF parsing) and provide a code example demonstrating how to use the relocation types.
* **代码推理 (Implicit):** The deduction of `stringName` and `intName` constitutes code reasoning.
* **命令行参数:**  State that this snippet doesn't directly handle them.
* **易犯错的点:** Provide an example of a common misunderstanding.
* **功能归纳 (Part 3 Summary):**  Summarize the specific role of this code snippet within the larger ELF parsing context. Emphasize that it's about *defining the vocabulary* of relocation types.

This step-by-step thought process, moving from code observation to higher-level understanding and finally to concrete examples, allows for a comprehensive and accurate answer to the prompt.
这是 `go/src/debug/elf/elf.go` 文件的一部分，它定义了用于表示不同架构下 ELF 文件重定位类型的 Go 类型和常量。

**功能列举:**

1. **定义了多种 CPU 架构的重定位类型:** 代码中定义了 `R_AARCH64`, `R_ALPHA`, `R_ARM`, `R_386`, `R_MIPS`, `R_LARCH` 等类型，分别代表了 AArch64, Alpha, ARM, x86 (386), MIPS 和 LoongArch 架构的重定位类型。
2. **为每种架构定义了具体的重定位常量:**  每个 `R_架构名` 类型都有一系列以 `R_架构名_` 开头的常量，这些常量代表了该架构下具体的重定位类型，例如 `R_AARCH64_ABS64`，`R_ARM_REL32` 等。
3. **提供了将重定位类型转换为字符串的方法:**  每个 `R_架构名` 类型都实现了 `String()` 和 `GoString()` 方法。这两个方法都调用了 `stringName` 函数，将整数类型的重定位值转换为易于阅读的字符串表示。`GoString()` 方法通常用于调试输出，可能包含更详细的信息。

**推断的 Go 语言功能实现：ELF 文件解析**

这段代码是 Go 语言 `debug/elf` 包的一部分，该包用于解析和操作 ELF (Executable and Linkable Format) 文件。ELF 是一种常见的用于可执行文件、目标代码、共享库和核心转储的文件格式。

这段代码的具体功能是定义了在 ELF 文件中表示重定位信息的结构。重定位是链接器在将不同的目标文件组合成最终的可执行文件或共享库时执行的关键步骤。它涉及到修改代码和数据中的引用，以确保它们指向正确的内存地址。

**Go 代码举例说明:**

假设我们正在解析一个 ARM 架构的 ELF 文件，并且遇到了一个重定位条目。我们可以使用这段代码中定义的 `R_ARM` 类型来识别重定位的类型：

```go
package main

import (
	"debug/elf"
	"fmt"
	"os"
)

func main() {
	f, err := elf.Open("example.o") // 假设存在一个名为 example.o 的 ARM 目标文件
	if err != nil {
		fmt.Println("Error opening ELF file:", err)
		return
	}
	defer f.Close()

	// 假设我们找到了一个重定位段 (例如 ".rel.text") 并遍历其条目
	for _, section := range f.Sections {
		if section.Name == ".rel.text" {
			relData, err := section.Data()
			if err != nil {
				fmt.Println("Error reading relocation data:", err)
				return
			}

			// 这里需要根据 ELF 文件的具体格式来解析重定位条目
			// 假设每个条目占用 8 字节，前 4 字节是偏移量，后 4 字节包含类型和符号信息
			const relocationEntrySize = 8
			for i := 0; i < len(relData); i += relocationEntrySize {
				// ... (解析偏移量) ...

				// 假设类型信息在后 4 字节的低位，并根据 ARM 架构的 ELF 规范进行位操作提取类型
				relTypeRaw := uint32(relData[i+4]) | uint32(relData[i+5])<<8 | uint32(relData[i+6])<<16 | uint32(relData[i+7])<<24
				relType := elf.R_ARM(relTypeRaw & 0xFF) // 假设低 8 位是重定位类型

				fmt.Printf("Found relocation of type: %s\n", relType.String())

				// 根据重定位类型进行进一步处理
				if relType == elf.R_ARM_ABS32 {
					fmt.Println("This is an absolute 32-bit relocation.")
					// ... (进行特定于 ABS32 重定位的处理) ...
				}
			}
			break // 假设我们只处理第一个 ".rel.text" 段
		}
	}
}
```

**假设的输入与输出:**

假设 `example.o` 文件包含一个 `.rel.text` 重定位段，其中包含一个类型为 `R_ARM_ABS32` 的重定位条目。

**输出:**

```
Found relocation of type: R_ARM_ABS32
This is an absolute 32-bit relocation.
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。`debug/elf` 包通常被其他工具或库使用，这些工具或库可能会接收命令行参数来指定要解析的 ELF 文件路径等。例如，Go 提供的 `go tool objdump` 工具就使用了 `debug/elf` 包来解析 ELF 文件并显示其内容。你可以通过命令行运行 `go tool objdump -r example.o` 来查看 `example.o` 文件的重定位信息，该工具内部就会使用到 `debug/elf` 包。

**使用者易犯错的点:**

使用者在处理不同架构的 ELF 文件时，容易混淆不同架构的重定位类型。例如，可能会错误地将 ARM 的 `R_ARM_ABS32` 类型用于处理 x86 的 ELF 文件。正确的做法是根据 ELF 文件的 Machine 类型（在 ELF 头部中指定）选择正确的 `R_架构名` 类型。

**功能归纳 (第 3 部分):**

这部分代码的核心功能是 **定义了 Go 语言中用于表示各种 CPU 架构 ELF 文件重定位类型的枚举类型和常量**。它为 `debug/elf` 包提供了处理不同架构下重定位信息的基础数据结构，使得程序能够以类型安全的方式识别和处理 ELF 文件中的重定位条目。它定义了处理 ELF 文件中重定位信息的“词汇表”。

Prompt: 
```
这是路径为go/src/debug/elf/elf.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第3部分，共5部分，请归纳一下它的功能

"""
T128_ABS_LO12_NC"},
	{18, "R_AARCH64_P32_TSTBR14"},
	{19, "R_AARCH64_P32_CONDBR19"},
	{20, "R_AARCH64_P32_JUMP26"},
	{21, "R_AARCH64_P32_CALL26"},
	{25, "R_AARCH64_P32_GOT_LD_PREL19"},
	{26, "R_AARCH64_P32_ADR_GOT_PAGE"},
	{27, "R_AARCH64_P32_LD32_GOT_LO12_NC"},
	{81, "R_AARCH64_P32_TLSGD_ADR_PAGE21"},
	{82, "R_AARCH64_P32_TLSGD_ADD_LO12_NC"},
	{103, "R_AARCH64_P32_TLSIE_ADR_GOTTPREL_PAGE21"},
	{104, "R_AARCH64_P32_TLSIE_LD32_GOTTPREL_LO12_NC"},
	{105, "R_AARCH64_P32_TLSIE_LD_GOTTPREL_PREL19"},
	{106, "R_AARCH64_P32_TLSLE_MOVW_TPREL_G1"},
	{107, "R_AARCH64_P32_TLSLE_MOVW_TPREL_G0"},
	{108, "R_AARCH64_P32_TLSLE_MOVW_TPREL_G0_NC"},
	{109, "R_AARCH64_P32_TLSLE_ADD_TPREL_HI12"},
	{110, "R_AARCH64_P32_TLSLE_ADD_TPREL_LO12"},
	{111, "R_AARCH64_P32_TLSLE_ADD_TPREL_LO12_NC"},
	{122, "R_AARCH64_P32_TLSDESC_LD_PREL19"},
	{123, "R_AARCH64_P32_TLSDESC_ADR_PREL21"},
	{124, "R_AARCH64_P32_TLSDESC_ADR_PAGE21"},
	{125, "R_AARCH64_P32_TLSDESC_LD32_LO12_NC"},
	{126, "R_AARCH64_P32_TLSDESC_ADD_LO12_NC"},
	{127, "R_AARCH64_P32_TLSDESC_CALL"},
	{180, "R_AARCH64_P32_COPY"},
	{181, "R_AARCH64_P32_GLOB_DAT"},
	{182, "R_AARCH64_P32_JUMP_SLOT"},
	{183, "R_AARCH64_P32_RELATIVE"},
	{184, "R_AARCH64_P32_TLS_DTPMOD"},
	{185, "R_AARCH64_P32_TLS_DTPREL"},
	{186, "R_AARCH64_P32_TLS_TPREL"},
	{187, "R_AARCH64_P32_TLSDESC"},
	{188, "R_AARCH64_P32_IRELATIVE"},
	{256, "R_AARCH64_NULL"},
	{257, "R_AARCH64_ABS64"},
	{258, "R_AARCH64_ABS32"},
	{259, "R_AARCH64_ABS16"},
	{260, "R_AARCH64_PREL64"},
	{261, "R_AARCH64_PREL32"},
	{262, "R_AARCH64_PREL16"},
	{263, "R_AARCH64_MOVW_UABS_G0"},
	{264, "R_AARCH64_MOVW_UABS_G0_NC"},
	{265, "R_AARCH64_MOVW_UABS_G1"},
	{266, "R_AARCH64_MOVW_UABS_G1_NC"},
	{267, "R_AARCH64_MOVW_UABS_G2"},
	{268, "R_AARCH64_MOVW_UABS_G2_NC"},
	{269, "R_AARCH64_MOVW_UABS_G3"},
	{270, "R_AARCH64_MOVW_SABS_G0"},
	{271, "R_AARCH64_MOVW_SABS_G1"},
	{272, "R_AARCH64_MOVW_SABS_G2"},
	{273, "R_AARCH64_LD_PREL_LO19"},
	{274, "R_AARCH64_ADR_PREL_LO21"},
	{275, "R_AARCH64_ADR_PREL_PG_HI21"},
	{276, "R_AARCH64_ADR_PREL_PG_HI21_NC"},
	{277, "R_AARCH64_ADD_ABS_LO12_NC"},
	{278, "R_AARCH64_LDST8_ABS_LO12_NC"},
	{279, "R_AARCH64_TSTBR14"},
	{280, "R_AARCH64_CONDBR19"},
	{282, "R_AARCH64_JUMP26"},
	{283, "R_AARCH64_CALL26"},
	{284, "R_AARCH64_LDST16_ABS_LO12_NC"},
	{285, "R_AARCH64_LDST32_ABS_LO12_NC"},
	{286, "R_AARCH64_LDST64_ABS_LO12_NC"},
	{299, "R_AARCH64_LDST128_ABS_LO12_NC"},
	{309, "R_AARCH64_GOT_LD_PREL19"},
	{310, "R_AARCH64_LD64_GOTOFF_LO15"},
	{311, "R_AARCH64_ADR_GOT_PAGE"},
	{312, "R_AARCH64_LD64_GOT_LO12_NC"},
	{313, "R_AARCH64_LD64_GOTPAGE_LO15"},
	{512, "R_AARCH64_TLSGD_ADR_PREL21"},
	{513, "R_AARCH64_TLSGD_ADR_PAGE21"},
	{514, "R_AARCH64_TLSGD_ADD_LO12_NC"},
	{515, "R_AARCH64_TLSGD_MOVW_G1"},
	{516, "R_AARCH64_TLSGD_MOVW_G0_NC"},
	{517, "R_AARCH64_TLSLD_ADR_PREL21"},
	{518, "R_AARCH64_TLSLD_ADR_PAGE21"},
	{539, "R_AARCH64_TLSIE_MOVW_GOTTPREL_G1"},
	{540, "R_AARCH64_TLSIE_MOVW_GOTTPREL_G0_NC"},
	{541, "R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21"},
	{542, "R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC"},
	{543, "R_AARCH64_TLSIE_LD_GOTTPREL_PREL19"},
	{544, "R_AARCH64_TLSLE_MOVW_TPREL_G2"},
	{545, "R_AARCH64_TLSLE_MOVW_TPREL_G1"},
	{546, "R_AARCH64_TLSLE_MOVW_TPREL_G1_NC"},
	{547, "R_AARCH64_TLSLE_MOVW_TPREL_G0"},
	{548, "R_AARCH64_TLSLE_MOVW_TPREL_G0_NC"},
	{549, "R_AARCH64_TLSLE_ADD_TPREL_HI12"},
	{550, "R_AARCH64_TLSLE_ADD_TPREL_LO12"},
	{551, "R_AARCH64_TLSLE_ADD_TPREL_LO12_NC"},
	{560, "R_AARCH64_TLSDESC_LD_PREL19"},
	{561, "R_AARCH64_TLSDESC_ADR_PREL21"},
	{562, "R_AARCH64_TLSDESC_ADR_PAGE21"},
	{563, "R_AARCH64_TLSDESC_LD64_LO12_NC"},
	{564, "R_AARCH64_TLSDESC_ADD_LO12_NC"},
	{565, "R_AARCH64_TLSDESC_OFF_G1"},
	{566, "R_AARCH64_TLSDESC_OFF_G0_NC"},
	{567, "R_AARCH64_TLSDESC_LDR"},
	{568, "R_AARCH64_TLSDESC_ADD"},
	{569, "R_AARCH64_TLSDESC_CALL"},
	{570, "R_AARCH64_TLSLE_LDST128_TPREL_LO12"},
	{571, "R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC"},
	{572, "R_AARCH64_TLSLD_LDST128_DTPREL_LO12"},
	{573, "R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC"},
	{1024, "R_AARCH64_COPY"},
	{1025, "R_AARCH64_GLOB_DAT"},
	{1026, "R_AARCH64_JUMP_SLOT"},
	{1027, "R_AARCH64_RELATIVE"},
	{1028, "R_AARCH64_TLS_DTPMOD64"},
	{1029, "R_AARCH64_TLS_DTPREL64"},
	{1030, "R_AARCH64_TLS_TPREL64"},
	{1031, "R_AARCH64_TLSDESC"},
	{1032, "R_AARCH64_IRELATIVE"},
}

func (i R_AARCH64) String() string   { return stringName(uint32(i), raarch64Strings, false) }
func (i R_AARCH64) GoString() string { return stringName(uint32(i), raarch64Strings, true) }

// Relocation types for Alpha.
type R_ALPHA int

const (
	R_ALPHA_NONE           R_ALPHA = 0  /* No reloc */
	R_ALPHA_REFLONG        R_ALPHA = 1  /* Direct 32 bit */
	R_ALPHA_REFQUAD        R_ALPHA = 2  /* Direct 64 bit */
	R_ALPHA_GPREL32        R_ALPHA = 3  /* GP relative 32 bit */
	R_ALPHA_LITERAL        R_ALPHA = 4  /* GP relative 16 bit w/optimization */
	R_ALPHA_LITUSE         R_ALPHA = 5  /* Optimization hint for LITERAL */
	R_ALPHA_GPDISP         R_ALPHA = 6  /* Add displacement to GP */
	R_ALPHA_BRADDR         R_ALPHA = 7  /* PC+4 relative 23 bit shifted */
	R_ALPHA_HINT           R_ALPHA = 8  /* PC+4 relative 16 bit shifted */
	R_ALPHA_SREL16         R_ALPHA = 9  /* PC relative 16 bit */
	R_ALPHA_SREL32         R_ALPHA = 10 /* PC relative 32 bit */
	R_ALPHA_SREL64         R_ALPHA = 11 /* PC relative 64 bit */
	R_ALPHA_OP_PUSH        R_ALPHA = 12 /* OP stack push */
	R_ALPHA_OP_STORE       R_ALPHA = 13 /* OP stack pop and store */
	R_ALPHA_OP_PSUB        R_ALPHA = 14 /* OP stack subtract */
	R_ALPHA_OP_PRSHIFT     R_ALPHA = 15 /* OP stack right shift */
	R_ALPHA_GPVALUE        R_ALPHA = 16
	R_ALPHA_GPRELHIGH      R_ALPHA = 17
	R_ALPHA_GPRELLOW       R_ALPHA = 18
	R_ALPHA_IMMED_GP_16    R_ALPHA = 19
	R_ALPHA_IMMED_GP_HI32  R_ALPHA = 20
	R_ALPHA_IMMED_SCN_HI32 R_ALPHA = 21
	R_ALPHA_IMMED_BR_HI32  R_ALPHA = 22
	R_ALPHA_IMMED_LO32     R_ALPHA = 23
	R_ALPHA_COPY           R_ALPHA = 24 /* Copy symbol at runtime */
	R_ALPHA_GLOB_DAT       R_ALPHA = 25 /* Create GOT entry */
	R_ALPHA_JMP_SLOT       R_ALPHA = 26 /* Create PLT entry */
	R_ALPHA_RELATIVE       R_ALPHA = 27 /* Adjust by program base */
)

var ralphaStrings = []intName{
	{0, "R_ALPHA_NONE"},
	{1, "R_ALPHA_REFLONG"},
	{2, "R_ALPHA_REFQUAD"},
	{3, "R_ALPHA_GPREL32"},
	{4, "R_ALPHA_LITERAL"},
	{5, "R_ALPHA_LITUSE"},
	{6, "R_ALPHA_GPDISP"},
	{7, "R_ALPHA_BRADDR"},
	{8, "R_ALPHA_HINT"},
	{9, "R_ALPHA_SREL16"},
	{10, "R_ALPHA_SREL32"},
	{11, "R_ALPHA_SREL64"},
	{12, "R_ALPHA_OP_PUSH"},
	{13, "R_ALPHA_OP_STORE"},
	{14, "R_ALPHA_OP_PSUB"},
	{15, "R_ALPHA_OP_PRSHIFT"},
	{16, "R_ALPHA_GPVALUE"},
	{17, "R_ALPHA_GPRELHIGH"},
	{18, "R_ALPHA_GPRELLOW"},
	{19, "R_ALPHA_IMMED_GP_16"},
	{20, "R_ALPHA_IMMED_GP_HI32"},
	{21, "R_ALPHA_IMMED_SCN_HI32"},
	{22, "R_ALPHA_IMMED_BR_HI32"},
	{23, "R_ALPHA_IMMED_LO32"},
	{24, "R_ALPHA_COPY"},
	{25, "R_ALPHA_GLOB_DAT"},
	{26, "R_ALPHA_JMP_SLOT"},
	{27, "R_ALPHA_RELATIVE"},
}

func (i R_ALPHA) String() string   { return stringName(uint32(i), ralphaStrings, false) }
func (i R_ALPHA) GoString() string { return stringName(uint32(i), ralphaStrings, true) }

// Relocation types for ARM.
type R_ARM int

const (
	R_ARM_NONE               R_ARM = 0 /* No relocation. */
	R_ARM_PC24               R_ARM = 1
	R_ARM_ABS32              R_ARM = 2
	R_ARM_REL32              R_ARM = 3
	R_ARM_PC13               R_ARM = 4
	R_ARM_ABS16              R_ARM = 5
	R_ARM_ABS12              R_ARM = 6
	R_ARM_THM_ABS5           R_ARM = 7
	R_ARM_ABS8               R_ARM = 8
	R_ARM_SBREL32            R_ARM = 9
	R_ARM_THM_PC22           R_ARM = 10
	R_ARM_THM_PC8            R_ARM = 11
	R_ARM_AMP_VCALL9         R_ARM = 12
	R_ARM_SWI24              R_ARM = 13
	R_ARM_THM_SWI8           R_ARM = 14
	R_ARM_XPC25              R_ARM = 15
	R_ARM_THM_XPC22          R_ARM = 16
	R_ARM_TLS_DTPMOD32       R_ARM = 17
	R_ARM_TLS_DTPOFF32       R_ARM = 18
	R_ARM_TLS_TPOFF32        R_ARM = 19
	R_ARM_COPY               R_ARM = 20 /* Copy data from shared object. */
	R_ARM_GLOB_DAT           R_ARM = 21 /* Set GOT entry to data address. */
	R_ARM_JUMP_SLOT          R_ARM = 22 /* Set GOT entry to code address. */
	R_ARM_RELATIVE           R_ARM = 23 /* Add load address of shared object. */
	R_ARM_GOTOFF             R_ARM = 24 /* Add GOT-relative symbol address. */
	R_ARM_GOTPC              R_ARM = 25 /* Add PC-relative GOT table address. */
	R_ARM_GOT32              R_ARM = 26 /* Add PC-relative GOT offset. */
	R_ARM_PLT32              R_ARM = 27 /* Add PC-relative PLT offset. */
	R_ARM_CALL               R_ARM = 28
	R_ARM_JUMP24             R_ARM = 29
	R_ARM_THM_JUMP24         R_ARM = 30
	R_ARM_BASE_ABS           R_ARM = 31
	R_ARM_ALU_PCREL_7_0      R_ARM = 32
	R_ARM_ALU_PCREL_15_8     R_ARM = 33
	R_ARM_ALU_PCREL_23_15    R_ARM = 34
	R_ARM_LDR_SBREL_11_10_NC R_ARM = 35
	R_ARM_ALU_SBREL_19_12_NC R_ARM = 36
	R_ARM_ALU_SBREL_27_20_CK R_ARM = 37
	R_ARM_TARGET1            R_ARM = 38
	R_ARM_SBREL31            R_ARM = 39
	R_ARM_V4BX               R_ARM = 40
	R_ARM_TARGET2            R_ARM = 41
	R_ARM_PREL31             R_ARM = 42
	R_ARM_MOVW_ABS_NC        R_ARM = 43
	R_ARM_MOVT_ABS           R_ARM = 44
	R_ARM_MOVW_PREL_NC       R_ARM = 45
	R_ARM_MOVT_PREL          R_ARM = 46
	R_ARM_THM_MOVW_ABS_NC    R_ARM = 47
	R_ARM_THM_MOVT_ABS       R_ARM = 48
	R_ARM_THM_MOVW_PREL_NC   R_ARM = 49
	R_ARM_THM_MOVT_PREL      R_ARM = 50
	R_ARM_THM_JUMP19         R_ARM = 51
	R_ARM_THM_JUMP6          R_ARM = 52
	R_ARM_THM_ALU_PREL_11_0  R_ARM = 53
	R_ARM_THM_PC12           R_ARM = 54
	R_ARM_ABS32_NOI          R_ARM = 55
	R_ARM_REL32_NOI          R_ARM = 56
	R_ARM_ALU_PC_G0_NC       R_ARM = 57
	R_ARM_ALU_PC_G0          R_ARM = 58
	R_ARM_ALU_PC_G1_NC       R_ARM = 59
	R_ARM_ALU_PC_G1          R_ARM = 60
	R_ARM_ALU_PC_G2          R_ARM = 61
	R_ARM_LDR_PC_G1          R_ARM = 62
	R_ARM_LDR_PC_G2          R_ARM = 63
	R_ARM_LDRS_PC_G0         R_ARM = 64
	R_ARM_LDRS_PC_G1         R_ARM = 65
	R_ARM_LDRS_PC_G2         R_ARM = 66
	R_ARM_LDC_PC_G0          R_ARM = 67
	R_ARM_LDC_PC_G1          R_ARM = 68
	R_ARM_LDC_PC_G2          R_ARM = 69
	R_ARM_ALU_SB_G0_NC       R_ARM = 70
	R_ARM_ALU_SB_G0          R_ARM = 71
	R_ARM_ALU_SB_G1_NC       R_ARM = 72
	R_ARM_ALU_SB_G1          R_ARM = 73
	R_ARM_ALU_SB_G2          R_ARM = 74
	R_ARM_LDR_SB_G0          R_ARM = 75
	R_ARM_LDR_SB_G1          R_ARM = 76
	R_ARM_LDR_SB_G2          R_ARM = 77
	R_ARM_LDRS_SB_G0         R_ARM = 78
	R_ARM_LDRS_SB_G1         R_ARM = 79
	R_ARM_LDRS_SB_G2         R_ARM = 80
	R_ARM_LDC_SB_G0          R_ARM = 81
	R_ARM_LDC_SB_G1          R_ARM = 82
	R_ARM_LDC_SB_G2          R_ARM = 83
	R_ARM_MOVW_BREL_NC       R_ARM = 84
	R_ARM_MOVT_BREL          R_ARM = 85
	R_ARM_MOVW_BREL          R_ARM = 86
	R_ARM_THM_MOVW_BREL_NC   R_ARM = 87
	R_ARM_THM_MOVT_BREL      R_ARM = 88
	R_ARM_THM_MOVW_BREL      R_ARM = 89
	R_ARM_TLS_GOTDESC        R_ARM = 90
	R_ARM_TLS_CALL           R_ARM = 91
	R_ARM_TLS_DESCSEQ        R_ARM = 92
	R_ARM_THM_TLS_CALL       R_ARM = 93
	R_ARM_PLT32_ABS          R_ARM = 94
	R_ARM_GOT_ABS            R_ARM = 95
	R_ARM_GOT_PREL           R_ARM = 96
	R_ARM_GOT_BREL12         R_ARM = 97
	R_ARM_GOTOFF12           R_ARM = 98
	R_ARM_GOTRELAX           R_ARM = 99
	R_ARM_GNU_VTENTRY        R_ARM = 100
	R_ARM_GNU_VTINHERIT      R_ARM = 101
	R_ARM_THM_JUMP11         R_ARM = 102
	R_ARM_THM_JUMP8          R_ARM = 103
	R_ARM_TLS_GD32           R_ARM = 104
	R_ARM_TLS_LDM32          R_ARM = 105
	R_ARM_TLS_LDO32          R_ARM = 106
	R_ARM_TLS_IE32           R_ARM = 107
	R_ARM_TLS_LE32           R_ARM = 108
	R_ARM_TLS_LDO12          R_ARM = 109
	R_ARM_TLS_LE12           R_ARM = 110
	R_ARM_TLS_IE12GP         R_ARM = 111
	R_ARM_PRIVATE_0          R_ARM = 112
	R_ARM_PRIVATE_1          R_ARM = 113
	R_ARM_PRIVATE_2          R_ARM = 114
	R_ARM_PRIVATE_3          R_ARM = 115
	R_ARM_PRIVATE_4          R_ARM = 116
	R_ARM_PRIVATE_5          R_ARM = 117
	R_ARM_PRIVATE_6          R_ARM = 118
	R_ARM_PRIVATE_7          R_ARM = 119
	R_ARM_PRIVATE_8          R_ARM = 120
	R_ARM_PRIVATE_9          R_ARM = 121
	R_ARM_PRIVATE_10         R_ARM = 122
	R_ARM_PRIVATE_11         R_ARM = 123
	R_ARM_PRIVATE_12         R_ARM = 124
	R_ARM_PRIVATE_13         R_ARM = 125
	R_ARM_PRIVATE_14         R_ARM = 126
	R_ARM_PRIVATE_15         R_ARM = 127
	R_ARM_ME_TOO             R_ARM = 128
	R_ARM_THM_TLS_DESCSEQ16  R_ARM = 129
	R_ARM_THM_TLS_DESCSEQ32  R_ARM = 130
	R_ARM_THM_GOT_BREL12     R_ARM = 131
	R_ARM_THM_ALU_ABS_G0_NC  R_ARM = 132
	R_ARM_THM_ALU_ABS_G1_NC  R_ARM = 133
	R_ARM_THM_ALU_ABS_G2_NC  R_ARM = 134
	R_ARM_THM_ALU_ABS_G3     R_ARM = 135
	R_ARM_IRELATIVE          R_ARM = 160
	R_ARM_RXPC25             R_ARM = 249
	R_ARM_RSBREL32           R_ARM = 250
	R_ARM_THM_RPC22          R_ARM = 251
	R_ARM_RREL32             R_ARM = 252
	R_ARM_RABS32             R_ARM = 253
	R_ARM_RPC24              R_ARM = 254
	R_ARM_RBASE              R_ARM = 255
)

var rarmStrings = []intName{
	{0, "R_ARM_NONE"},
	{1, "R_ARM_PC24"},
	{2, "R_ARM_ABS32"},
	{3, "R_ARM_REL32"},
	{4, "R_ARM_PC13"},
	{5, "R_ARM_ABS16"},
	{6, "R_ARM_ABS12"},
	{7, "R_ARM_THM_ABS5"},
	{8, "R_ARM_ABS8"},
	{9, "R_ARM_SBREL32"},
	{10, "R_ARM_THM_PC22"},
	{11, "R_ARM_THM_PC8"},
	{12, "R_ARM_AMP_VCALL9"},
	{13, "R_ARM_SWI24"},
	{14, "R_ARM_THM_SWI8"},
	{15, "R_ARM_XPC25"},
	{16, "R_ARM_THM_XPC22"},
	{17, "R_ARM_TLS_DTPMOD32"},
	{18, "R_ARM_TLS_DTPOFF32"},
	{19, "R_ARM_TLS_TPOFF32"},
	{20, "R_ARM_COPY"},
	{21, "R_ARM_GLOB_DAT"},
	{22, "R_ARM_JUMP_SLOT"},
	{23, "R_ARM_RELATIVE"},
	{24, "R_ARM_GOTOFF"},
	{25, "R_ARM_GOTPC"},
	{26, "R_ARM_GOT32"},
	{27, "R_ARM_PLT32"},
	{28, "R_ARM_CALL"},
	{29, "R_ARM_JUMP24"},
	{30, "R_ARM_THM_JUMP24"},
	{31, "R_ARM_BASE_ABS"},
	{32, "R_ARM_ALU_PCREL_7_0"},
	{33, "R_ARM_ALU_PCREL_15_8"},
	{34, "R_ARM_ALU_PCREL_23_15"},
	{35, "R_ARM_LDR_SBREL_11_10_NC"},
	{36, "R_ARM_ALU_SBREL_19_12_NC"},
	{37, "R_ARM_ALU_SBREL_27_20_CK"},
	{38, "R_ARM_TARGET1"},
	{39, "R_ARM_SBREL31"},
	{40, "R_ARM_V4BX"},
	{41, "R_ARM_TARGET2"},
	{42, "R_ARM_PREL31"},
	{43, "R_ARM_MOVW_ABS_NC"},
	{44, "R_ARM_MOVT_ABS"},
	{45, "R_ARM_MOVW_PREL_NC"},
	{46, "R_ARM_MOVT_PREL"},
	{47, "R_ARM_THM_MOVW_ABS_NC"},
	{48, "R_ARM_THM_MOVT_ABS"},
	{49, "R_ARM_THM_MOVW_PREL_NC"},
	{50, "R_ARM_THM_MOVT_PREL"},
	{51, "R_ARM_THM_JUMP19"},
	{52, "R_ARM_THM_JUMP6"},
	{53, "R_ARM_THM_ALU_PREL_11_0"},
	{54, "R_ARM_THM_PC12"},
	{55, "R_ARM_ABS32_NOI"},
	{56, "R_ARM_REL32_NOI"},
	{57, "R_ARM_ALU_PC_G0_NC"},
	{58, "R_ARM_ALU_PC_G0"},
	{59, "R_ARM_ALU_PC_G1_NC"},
	{60, "R_ARM_ALU_PC_G1"},
	{61, "R_ARM_ALU_PC_G2"},
	{62, "R_ARM_LDR_PC_G1"},
	{63, "R_ARM_LDR_PC_G2"},
	{64, "R_ARM_LDRS_PC_G0"},
	{65, "R_ARM_LDRS_PC_G1"},
	{66, "R_ARM_LDRS_PC_G2"},
	{67, "R_ARM_LDC_PC_G0"},
	{68, "R_ARM_LDC_PC_G1"},
	{69, "R_ARM_LDC_PC_G2"},
	{70, "R_ARM_ALU_SB_G0_NC"},
	{71, "R_ARM_ALU_SB_G0"},
	{72, "R_ARM_ALU_SB_G1_NC"},
	{73, "R_ARM_ALU_SB_G1"},
	{74, "R_ARM_ALU_SB_G2"},
	{75, "R_ARM_LDR_SB_G0"},
	{76, "R_ARM_LDR_SB_G1"},
	{77, "R_ARM_LDR_SB_G2"},
	{78, "R_ARM_LDRS_SB_G0"},
	{79, "R_ARM_LDRS_SB_G1"},
	{80, "R_ARM_LDRS_SB_G2"},
	{81, "R_ARM_LDC_SB_G0"},
	{82, "R_ARM_LDC_SB_G1"},
	{83, "R_ARM_LDC_SB_G2"},
	{84, "R_ARM_MOVW_BREL_NC"},
	{85, "R_ARM_MOVT_BREL"},
	{86, "R_ARM_MOVW_BREL"},
	{87, "R_ARM_THM_MOVW_BREL_NC"},
	{88, "R_ARM_THM_MOVT_BREL"},
	{89, "R_ARM_THM_MOVW_BREL"},
	{90, "R_ARM_TLS_GOTDESC"},
	{91, "R_ARM_TLS_CALL"},
	{92, "R_ARM_TLS_DESCSEQ"},
	{93, "R_ARM_THM_TLS_CALL"},
	{94, "R_ARM_PLT32_ABS"},
	{95, "R_ARM_GOT_ABS"},
	{96, "R_ARM_GOT_PREL"},
	{97, "R_ARM_GOT_BREL12"},
	{98, "R_ARM_GOTOFF12"},
	{99, "R_ARM_GOTRELAX"},
	{100, "R_ARM_GNU_VTENTRY"},
	{101, "R_ARM_GNU_VTINHERIT"},
	{102, "R_ARM_THM_JUMP11"},
	{103, "R_ARM_THM_JUMP8"},
	{104, "R_ARM_TLS_GD32"},
	{105, "R_ARM_TLS_LDM32"},
	{106, "R_ARM_TLS_LDO32"},
	{107, "R_ARM_TLS_IE32"},
	{108, "R_ARM_TLS_LE32"},
	{109, "R_ARM_TLS_LDO12"},
	{110, "R_ARM_TLS_LE12"},
	{111, "R_ARM_TLS_IE12GP"},
	{112, "R_ARM_PRIVATE_0"},
	{113, "R_ARM_PRIVATE_1"},
	{114, "R_ARM_PRIVATE_2"},
	{115, "R_ARM_PRIVATE_3"},
	{116, "R_ARM_PRIVATE_4"},
	{117, "R_ARM_PRIVATE_5"},
	{118, "R_ARM_PRIVATE_6"},
	{119, "R_ARM_PRIVATE_7"},
	{120, "R_ARM_PRIVATE_8"},
	{121, "R_ARM_PRIVATE_9"},
	{122, "R_ARM_PRIVATE_10"},
	{123, "R_ARM_PRIVATE_11"},
	{124, "R_ARM_PRIVATE_12"},
	{125, "R_ARM_PRIVATE_13"},
	{126, "R_ARM_PRIVATE_14"},
	{127, "R_ARM_PRIVATE_15"},
	{128, "R_ARM_ME_TOO"},
	{129, "R_ARM_THM_TLS_DESCSEQ16"},
	{130, "R_ARM_THM_TLS_DESCSEQ32"},
	{131, "R_ARM_THM_GOT_BREL12"},
	{132, "R_ARM_THM_ALU_ABS_G0_NC"},
	{133, "R_ARM_THM_ALU_ABS_G1_NC"},
	{134, "R_ARM_THM_ALU_ABS_G2_NC"},
	{135, "R_ARM_THM_ALU_ABS_G3"},
	{160, "R_ARM_IRELATIVE"},
	{249, "R_ARM_RXPC25"},
	{250, "R_ARM_RSBREL32"},
	{251, "R_ARM_THM_RPC22"},
	{252, "R_ARM_RREL32"},
	{253, "R_ARM_RABS32"},
	{254, "R_ARM_RPC24"},
	{255, "R_ARM_RBASE"},
}

func (i R_ARM) String() string   { return stringName(uint32(i), rarmStrings, false) }
func (i R_ARM) GoString() string { return stringName(uint32(i), rarmStrings, true) }

// Relocation types for 386.
type R_386 int

const (
	R_386_NONE          R_386 = 0  /* No relocation. */
	R_386_32            R_386 = 1  /* Add symbol value. */
	R_386_PC32          R_386 = 2  /* Add PC-relative symbol value. */
	R_386_GOT32         R_386 = 3  /* Add PC-relative GOT offset. */
	R_386_PLT32         R_386 = 4  /* Add PC-relative PLT offset. */
	R_386_COPY          R_386 = 5  /* Copy data from shared object. */
	R_386_GLOB_DAT      R_386 = 6  /* Set GOT entry to data address. */
	R_386_JMP_SLOT      R_386 = 7  /* Set GOT entry to code address. */
	R_386_RELATIVE      R_386 = 8  /* Add load address of shared object. */
	R_386_GOTOFF        R_386 = 9  /* Add GOT-relative symbol address. */
	R_386_GOTPC         R_386 = 10 /* Add PC-relative GOT table address. */
	R_386_32PLT         R_386 = 11
	R_386_TLS_TPOFF     R_386 = 14 /* Negative offset in static TLS block */
	R_386_TLS_IE        R_386 = 15 /* Absolute address of GOT for -ve static TLS */
	R_386_TLS_GOTIE     R_386 = 16 /* GOT entry for negative static TLS block */
	R_386_TLS_LE        R_386 = 17 /* Negative offset relative to static TLS */
	R_386_TLS_GD        R_386 = 18 /* 32 bit offset to GOT (index,off) pair */
	R_386_TLS_LDM       R_386 = 19 /* 32 bit offset to GOT (index,zero) pair */
	R_386_16            R_386 = 20
	R_386_PC16          R_386 = 21
	R_386_8             R_386 = 22
	R_386_PC8           R_386 = 23
	R_386_TLS_GD_32     R_386 = 24 /* 32 bit offset to GOT (index,off) pair */
	R_386_TLS_GD_PUSH   R_386 = 25 /* pushl instruction for Sun ABI GD sequence */
	R_386_TLS_GD_CALL   R_386 = 26 /* call instruction for Sun ABI GD sequence */
	R_386_TLS_GD_POP    R_386 = 27 /* popl instruction for Sun ABI GD sequence */
	R_386_TLS_LDM_32    R_386 = 28 /* 32 bit offset to GOT (index,zero) pair */
	R_386_TLS_LDM_PUSH  R_386 = 29 /* pushl instruction for Sun ABI LD sequence */
	R_386_TLS_LDM_CALL  R_386 = 30 /* call instruction for Sun ABI LD sequence */
	R_386_TLS_LDM_POP   R_386 = 31 /* popl instruction for Sun ABI LD sequence */
	R_386_TLS_LDO_32    R_386 = 32 /* 32 bit offset from start of TLS block */
	R_386_TLS_IE_32     R_386 = 33 /* 32 bit offset to GOT static TLS offset entry */
	R_386_TLS_LE_32     R_386 = 34 /* 32 bit offset within static TLS block */
	R_386_TLS_DTPMOD32  R_386 = 35 /* GOT entry containing TLS index */
	R_386_TLS_DTPOFF32  R_386 = 36 /* GOT entry containing TLS offset */
	R_386_TLS_TPOFF32   R_386 = 37 /* GOT entry of -ve static TLS offset */
	R_386_SIZE32        R_386 = 38
	R_386_TLS_GOTDESC   R_386 = 39
	R_386_TLS_DESC_CALL R_386 = 40
	R_386_TLS_DESC      R_386 = 41
	R_386_IRELATIVE     R_386 = 42
	R_386_GOT32X        R_386 = 43
)

var r386Strings = []intName{
	{0, "R_386_NONE"},
	{1, "R_386_32"},
	{2, "R_386_PC32"},
	{3, "R_386_GOT32"},
	{4, "R_386_PLT32"},
	{5, "R_386_COPY"},
	{6, "R_386_GLOB_DAT"},
	{7, "R_386_JMP_SLOT"},
	{8, "R_386_RELATIVE"},
	{9, "R_386_GOTOFF"},
	{10, "R_386_GOTPC"},
	{11, "R_386_32PLT"},
	{14, "R_386_TLS_TPOFF"},
	{15, "R_386_TLS_IE"},
	{16, "R_386_TLS_GOTIE"},
	{17, "R_386_TLS_LE"},
	{18, "R_386_TLS_GD"},
	{19, "R_386_TLS_LDM"},
	{20, "R_386_16"},
	{21, "R_386_PC16"},
	{22, "R_386_8"},
	{23, "R_386_PC8"},
	{24, "R_386_TLS_GD_32"},
	{25, "R_386_TLS_GD_PUSH"},
	{26, "R_386_TLS_GD_CALL"},
	{27, "R_386_TLS_GD_POP"},
	{28, "R_386_TLS_LDM_32"},
	{29, "R_386_TLS_LDM_PUSH"},
	{30, "R_386_TLS_LDM_CALL"},
	{31, "R_386_TLS_LDM_POP"},
	{32, "R_386_TLS_LDO_32"},
	{33, "R_386_TLS_IE_32"},
	{34, "R_386_TLS_LE_32"},
	{35, "R_386_TLS_DTPMOD32"},
	{36, "R_386_TLS_DTPOFF32"},
	{37, "R_386_TLS_TPOFF32"},
	{38, "R_386_SIZE32"},
	{39, "R_386_TLS_GOTDESC"},
	{40, "R_386_TLS_DESC_CALL"},
	{41, "R_386_TLS_DESC"},
	{42, "R_386_IRELATIVE"},
	{43, "R_386_GOT32X"},
}

func (i R_386) String() string   { return stringName(uint32(i), r386Strings, false) }
func (i R_386) GoString() string { return stringName(uint32(i), r386Strings, true) }

// Relocation types for MIPS.
type R_MIPS int

const (
	R_MIPS_NONE          R_MIPS = 0
	R_MIPS_16            R_MIPS = 1
	R_MIPS_32            R_MIPS = 2
	R_MIPS_REL32         R_MIPS = 3
	R_MIPS_26            R_MIPS = 4
	R_MIPS_HI16          R_MIPS = 5  /* high 16 bits of symbol value */
	R_MIPS_LO16          R_MIPS = 6  /* low 16 bits of symbol value */
	R_MIPS_GPREL16       R_MIPS = 7  /* GP-relative reference  */
	R_MIPS_LITERAL       R_MIPS = 8  /* Reference to literal section  */
	R_MIPS_GOT16         R_MIPS = 9  /* Reference to global offset table */
	R_MIPS_PC16          R_MIPS = 10 /* 16 bit PC relative reference */
	R_MIPS_CALL16        R_MIPS = 11 /* 16 bit call through glbl offset tbl */
	R_MIPS_GPREL32       R_MIPS = 12
	R_MIPS_SHIFT5        R_MIPS = 16
	R_MIPS_SHIFT6        R_MIPS = 17
	R_MIPS_64            R_MIPS = 18
	R_MIPS_GOT_DISP      R_MIPS = 19
	R_MIPS_GOT_PAGE      R_MIPS = 20
	R_MIPS_GOT_OFST      R_MIPS = 21
	R_MIPS_GOT_HI16      R_MIPS = 22
	R_MIPS_GOT_LO16      R_MIPS = 23
	R_MIPS_SUB           R_MIPS = 24
	R_MIPS_INSERT_A      R_MIPS = 25
	R_MIPS_INSERT_B      R_MIPS = 26
	R_MIPS_DELETE        R_MIPS = 27
	R_MIPS_HIGHER        R_MIPS = 28
	R_MIPS_HIGHEST       R_MIPS = 29
	R_MIPS_CALL_HI16     R_MIPS = 30
	R_MIPS_CALL_LO16     R_MIPS = 31
	R_MIPS_SCN_DISP      R_MIPS = 32
	R_MIPS_REL16         R_MIPS = 33
	R_MIPS_ADD_IMMEDIATE R_MIPS = 34
	R_MIPS_PJUMP         R_MIPS = 35
	R_MIPS_RELGOT        R_MIPS = 36
	R_MIPS_JALR          R_MIPS = 37

	R_MIPS_TLS_DTPMOD32    R_MIPS = 38 /* Module number 32 bit */
	R_MIPS_TLS_DTPREL32    R_MIPS = 39 /* Module-relative offset 32 bit */
	R_MIPS_TLS_DTPMOD64    R_MIPS = 40 /* Module number 64 bit */
	R_MIPS_TLS_DTPREL64    R_MIPS = 41 /* Module-relative offset 64 bit */
	R_MIPS_TLS_GD          R_MIPS = 42 /* 16 bit GOT offset for GD */
	R_MIPS_TLS_LDM         R_MIPS = 43 /* 16 bit GOT offset for LDM */
	R_MIPS_TLS_DTPREL_HI16 R_MIPS = 44 /* Module-relative offset, high 16 bits */
	R_MIPS_TLS_DTPREL_LO16 R_MIPS = 45 /* Module-relative offset, low 16 bits */
	R_MIPS_TLS_GOTTPREL    R_MIPS = 46 /* 16 bit GOT offset for IE */
	R_MIPS_TLS_TPREL32     R_MIPS = 47 /* TP-relative offset, 32 bit */
	R_MIPS_TLS_TPREL64     R_MIPS = 48 /* TP-relative offset, 64 bit */
	R_MIPS_TLS_TPREL_HI16  R_MIPS = 49 /* TP-relative offset, high 16 bits */
	R_MIPS_TLS_TPREL_LO16  R_MIPS = 50 /* TP-relative offset, low 16 bits */

	R_MIPS_PC32 R_MIPS = 248 /* 32 bit PC relative reference */
)

var rmipsStrings = []intName{
	{0, "R_MIPS_NONE"},
	{1, "R_MIPS_16"},
	{2, "R_MIPS_32"},
	{3, "R_MIPS_REL32"},
	{4, "R_MIPS_26"},
	{5, "R_MIPS_HI16"},
	{6, "R_MIPS_LO16"},
	{7, "R_MIPS_GPREL16"},
	{8, "R_MIPS_LITERAL"},
	{9, "R_MIPS_GOT16"},
	{10, "R_MIPS_PC16"},
	{11, "R_MIPS_CALL16"},
	{12, "R_MIPS_GPREL32"},
	{16, "R_MIPS_SHIFT5"},
	{17, "R_MIPS_SHIFT6"},
	{18, "R_MIPS_64"},
	{19, "R_MIPS_GOT_DISP"},
	{20, "R_MIPS_GOT_PAGE"},
	{21, "R_MIPS_GOT_OFST"},
	{22, "R_MIPS_GOT_HI16"},
	{23, "R_MIPS_GOT_LO16"},
	{24, "R_MIPS_SUB"},
	{25, "R_MIPS_INSERT_A"},
	{26, "R_MIPS_INSERT_B"},
	{27, "R_MIPS_DELETE"},
	{28, "R_MIPS_HIGHER"},
	{29, "R_MIPS_HIGHEST"},
	{30, "R_MIPS_CALL_HI16"},
	{31, "R_MIPS_CALL_LO16"},
	{32, "R_MIPS_SCN_DISP"},
	{33, "R_MIPS_REL16"},
	{34, "R_MIPS_ADD_IMMEDIATE"},
	{35, "R_MIPS_PJUMP"},
	{36, "R_MIPS_RELGOT"},
	{37, "R_MIPS_JALR"},
	{38, "R_MIPS_TLS_DTPMOD32"},
	{39, "R_MIPS_TLS_DTPREL32"},
	{40, "R_MIPS_TLS_DTPMOD64"},
	{41, "R_MIPS_TLS_DTPREL64"},
	{42, "R_MIPS_TLS_GD"},
	{43, "R_MIPS_TLS_LDM"},
	{44, "R_MIPS_TLS_DTPREL_HI16"},
	{45, "R_MIPS_TLS_DTPREL_LO16"},
	{46, "R_MIPS_TLS_GOTTPREL"},
	{47, "R_MIPS_TLS_TPREL32"},
	{48, "R_MIPS_TLS_TPREL64"},
	{49, "R_MIPS_TLS_TPREL_HI16"},
	{50, "R_MIPS_TLS_TPREL_LO16"},
	{248, "R_MIPS_PC32"},
}

func (i R_MIPS) String() string   { return stringName(uint32(i), rmipsStrings, false) }
func (i R_MIPS) GoString() string { return stringName(uint32(i), rmipsStrings, true) }

// Relocation types for LoongArch.
type R_LARCH int

const (
	R_LARCH_NONE                       R_LARCH = 0
	R_LARCH_32                         R_LARCH = 1
	R_LARCH_64                         R_LARCH = 2
	R_LARCH_RELATIVE                   R_LARCH = 3
	R_LARCH_COPY                       R_LARCH = 4
	R_LARCH_JUMP_SLOT                  R_LARCH = 5
	R_LARCH_TLS_DTPMOD32               R_LARCH = 6
	R_LARCH_TLS_DTPMOD64               R_LARCH = 7
	R_LARCH_TLS_DTPREL32               R_LARCH = 8
	R_LARCH_TLS_DTPREL64               R_LARCH = 9
	R_LARCH_TLS_TPREL32                R_LARCH = 10
	R_LARCH_TLS_TPREL64                R_LARCH = 11
	R_LARCH_IRELATIVE                  R_LARCH = 12
	R_LARCH_MARK_LA                    R_LARCH = 20
	R_LARCH_MARK_PCREL                 R_LARCH = 21
	R_LARCH_SOP_PUSH_PCREL             R_LARCH = 22
	R_LARCH_SOP_PUSH_ABSOLUTE          R_LARCH = 23
	R_LARCH_SOP_PUSH_DUP               R_LARCH = 24
	R_LARCH_SOP_PUSH_GPREL             R_LARCH = 25
	R_LARCH_SOP_PUSH_TLS_TPREL         R_LARCH = 26
	R_LARCH_SOP_PUSH_TLS_GOT           R_LARCH = 27
	R_LARCH_SOP_PUSH_TLS_GD            R_LARCH = 28
	R_LARCH_SOP_PUSH_PLT_PCREL         R_LARCH = 29
	R_LARCH_SOP_ASSERT                 R_LARCH = 30
	R_LARCH_SOP_NOT                    R_LARCH = 31
	R_LARCH_SOP_SUB                    R_LARCH = 32
	R_LARCH_SOP_SL                     R_LARCH = 33
	R_LARCH_SOP_SR                     R_LARCH = 34
	R_LARCH_SOP_ADD                    R_LARCH = 35
	R_LARCH_SOP_AND                    R_LARCH = 36
	R_LARCH_SOP_IF_ELSE                R_LARCH = 37
	R_LARCH_SOP_POP_32_S_10_5          R_LARCH = 38
	R_LARCH_SOP_POP_32_U_10_12         R_LARCH = 39
	R_LARCH_SOP_POP_32_S_10_12         R_LARCH = 40
	R_LARCH_SOP_POP_32_S_10_16         R_LARCH = 41
	R_LARCH_SOP_POP_32_S_10_16_S2      R_LARCH = 42
	R_LARCH_SOP_POP_32_S_5_20          R_LARCH = 43
	R_LARCH_SOP_POP_32_S_0_5_10_16_S2  R_LARCH = 44
	R_LARCH_SOP_POP_32_S_0_10_10_16_S2 R_LARCH = 45
	R_LARCH_SOP_POP_32_U               R_LARCH = 46
	R_LARCH_ADD8                       R_LARCH = 47
	R_LARCH_ADD16                      R_LARCH = 48
	R_LARCH_ADD24                      R_LARCH = 49
	R_LARCH_ADD32                      R_LARCH = 50
	R_LARCH_ADD64                      R_LARCH = 51
	R_LARCH_SUB8                       R_LARCH = 52
	R_LARCH_SUB16                      R_LARCH = 53
	R_LARCH_SUB24                      R_LARCH = 54
	R_LARCH_SUB32                      R_LARCH = 55
	R_LARCH_SUB64                      R_LARCH = 56
	R_LARCH_GNU_VTINHERIT              R_LARCH = 57
	R_LARCH_GNU_VTENTRY                R_LARCH = 58
	R_LARCH_B16                        R_LARCH = 64
	R_LARCH_B21                        R_LARCH = 65
	R_LARCH_B26                        R_LARCH = 66
	R_LARCH_ABS_HI20                   R_LARCH = 67
	R_LARCH_ABS_LO12                   R_LARCH = 68
	R_LARCH_ABS64_LO20                 R_LARCH = 69
	R_LARCH_ABS64_HI12                 R_LARCH = 70
	R_LARCH_PCALA_HI20                 R_LARCH = 71
	R_LARCH_PCALA_LO12                 R_LARCH = 72
	R_LARCH_PCALA64_LO20               R_LARCH = 73
	R_LARCH_PCALA64_HI12               R_LARCH = 74
	R_LARCH_GOT_PC_HI20                R_LARCH = 75
	R_LARCH_GOT_PC_LO12                R_LARCH = 76
	R_LARCH_GOT64_PC_LO20              R_LARCH = 77
	R_LARCH_GOT64_PC_HI12              R_LARCH = 78
	R_LARCH_GOT_HI20                   R_LARCH = 79
	R_LARCH_GOT_LO12                   R_LARCH = 80
	R_LARCH_GOT64_LO20                 R_LARCH = 81
	R_LARCH_GOT64_HI12                 R_LARCH = 82
	R_LARCH_TLS_LE_HI20                R_LARCH = 83
	R_LARCH_TLS_LE_LO12                R_LARCH = 84
	R_LARCH_TLS_LE64_LO20              R_LARCH = 85
	R_LARCH_TLS_LE64_HI12              R_LARCH = 86
	R_LARCH_TLS_IE_PC_HI20             R_LARCH = 87
	R_LARCH_TLS_IE_PC_LO12             R_LARCH = 88
	R_LARCH_TLS_IE64_PC_LO20           R_LARCH = 89
	R_LARCH_TLS_IE64_PC_HI12           R_LARCH = 90
	R_LARCH_TLS_IE_HI20                R_LARCH = 91
	R_LARCH_TLS_IE_LO12                R_LARCH = 92
	R_LARCH_TLS_IE64_LO20              R_LARCH = 93
	R_LARCH_TLS_IE64_HI12              R_LARCH = 94
	R_LARCH_TLS_LD_PC_HI20             R_LARCH = 95
	R_LARCH_TLS_LD_HI20                R_LARCH = 96
	R_LARCH_TLS_GD_PC_HI20             R_LARCH = 97
	R_LARCH_TLS_GD_HI20                R_LARCH = 98
	R_LARCH_32_PCREL                   R_LARCH = 99
	R_LARCH_RELAX                      R_LARCH = 100
	R_LARCH_DELETE                     R_LARCH = 101
	R_LARCH_ALIGN                      R_LARCH = 102
	R_LARCH_PCREL20_S2                 R_LARCH = 103
	R_LARCH_CFA                        R_LARCH = 104
	R_LARCH_ADD6                       R_LARCH = 105
	R_LARCH_SUB6                       R_LARCH = 106
	R_LARCH_ADD_ULEB128                R_LARCH = 107
	R_LARCH_SUB_ULEB128                R_LARCH = 108
	R_LARCH_64_PCREL                   R_LARCH = 109
)

var rlarchStrings = []intName{
	{0, "R_LARCH_NONE"},
	{1, "R_LARCH_32"},
	{2, "R_LARCH_64"},
	{3, "R_LARCH_RELATIVE"},
	{4, "R_LARCH_COPY"},
	{5, "R_LARCH_JUMP_SLOT"},
	{6, "R_LARCH_TLS_DTPMOD32"},
	{7, "R_LARCH_TLS_DTPMOD64"},
	{8, "R_LARCH_TLS_DTPREL32"},
	{9, "R_LARCH_TLS_DTPREL64"},
	{10, "R_LARCH_TLS_TPREL32"},
	{11, "R_LARCH_TLS_TPREL64"},
	{12, "R_LARCH_IRELATIVE"},
	{20, "R_LARCH_MARK_LA"},
	{21, "R_LARCH_MARK_PCREL"},
	{22, "R_LARCH_SOP_PUSH_PCREL"},
	{23, "R_LARCH_SOP_PUSH_ABSOLUTE"},
	{24, "R_LARCH_SOP_PUSH_DUP"},
	{25, "R_LARCH_SOP_PUSH_GPREL"},
	{26, "R_LARCH_SOP_PUSH_TLS_TPREL"},
	{27, "R_LARCH_SOP_PUSH_TLS_GOT"},
	{28, "R_LARCH_SOP_PUSH_TLS_GD"},
	{29, "R_LARCH_SOP_PUSH_PLT_PCREL"},
	{30, "R_LARCH_SOP_ASSERT"},
	{31, "R_LARCH_SOP_NOT"},
	{32, "R_LARCH_SOP_SUB"},
	{33, "R_LARCH_SOP_SL"},
	{34, "R_LARCH_SOP_SR"},
	{35, "R_LARCH_SOP_ADD"},
	{36, "R_LARCH_SOP_AND"},
	{37, "R_LARCH_SOP_IF_ELSE"},
	{38, "R_LARCH_SOP_POP_32_S_10_5"},
	{39, "R_LARCH_SOP_POP_32_U_10_12"},
	{40, "R_LARCH_SOP_POP_32_S_10_12"},
	{41, "R_LARCH_SOP_POP_32_S_10_16"},
	{42, "R_LARCH_SOP_POP_32_S_10_16_S2"},
	{43, "R_LARCH_SOP_POP_32_S_5_20"},
	{44, "R_LARCH_SOP_POP_32_S_0_5_10_16_S2"},
	{45, "R_LARCH_SOP_POP_32_S_0_10_10_16_S2"},
	{46, "R_LARCH_SOP_POP_32_U"},
	{47, "R_LARCH_ADD8"},
	{48, "R_LARCH_ADD16"},
	{49, "R_LARCH_ADD24"},
	{50, "R_LARCH_ADD32"},
	{51, "R_LARCH_ADD64"},
	{52, "R_LARCH_SUB8"},
	{53, "R_LARCH_SUB16"},
	{54, "R_LARCH_SUB24"},
	{55, "R_LARCH_SUB32"},
	{56, "R_LARCH_SUB64"},
	{57, "R_LARCH_GNU_VTINHERIT"},
	{58, "R_LARCH_GNU_VTENTRY"},
	{64, "R_LARCH_B16"},
	{65, "R_LARCH_B21"},
	{66, "R_LARCH_B26"},
	{67, "R_LARCH_ABS_HI20"},
	{68, "R_LARCH_ABS_LO12"},
	{69, "R_LARCH_ABS64_LO20"},
	{70, "R_LARCH_ABS64_HI12"},
	{71, "R_LARCH_PCALA_HI20"},
	{72, "R_LARCH_PCALA_LO12"},
	{73, "R_LARCH_PCALA64_LO20"},
	{74, "R_LARCH_PCALA64_HI12"},
	{75, "R_LARCH_GOT_PC_HI20"},
	{76, "R_LARCH_GOT_PC_LO12"},
	{77, "R_LARCH_GOT64_PC_LO20"},
	{78, "R_LARCH_GOT64_PC_HI12"},
	{79, "R_LARCH_GOT_HI20"},
	{80, "R_LARCH_GOT_LO12"},
	{81, "R_LARCH_GOT64_LO20"},
	{82, "R_LARCH_GOT64_HI12"},
	{83, "R_LARCH_TLS_LE_HI20"},
	{84, "R_LARCH_TLS_LE_LO12"},
	{85, "R_LARCH_TLS_LE64_LO20"},
	{86, "R_LARCH_TLS_LE64_HI12"},
	{87, "R_LARCH_TLS_IE_PC_HI20"},
	{88, "R_LARCH_TLS_IE_PC_LO12"},
	{89, "R_LARCH_TLS_IE64_PC_LO20"},
	{90, "R_LARCH_TLS_IE64_PC_HI12"},
	{91, "R_LARCH_TLS_IE_HI20"},
	{92, "R_LARCH_TLS_IE_LO12"},
	{93, "R_LARCH_TLS_IE64_LO20"},
	{94, "R_LARCH_TLS_IE64_HI12"},
	{95, "R_LARCH_TLS_LD_PC_HI20"},
	{96, "R_LARCH_TLS_LD_HI20"},
	{97, "R_LARCH_TLS_GD_PC_HI20"},
	{98, "R_LARCH_TLS_GD_HI20"},
	{99, "R_LARCH_32_PCREL"},
	{100, "R_LARCH_RELAX"},
	{101, "R_LARCH_DELETE"},
	{102, "R_LARCH_ALIGN"},
	{103, "R_LARCH_PCREL20_S2"},
	{104, "R_LARCH_CFA"},
	{105, "R_LARCH_ADD6"},
	{106, "R_LARCH_SUB6"},
	{107, "R_LARCH_ADD_ULEB128"},
	{108, "R_LARCH_SUB_ULEB128"},
	{109, "R_LARCH_64_PCREL"},
}

func (i R_LARCH) String() string   { return stringName(uint32(i), rlarchStrings, false) }
func (i R_LARCH) GoString() string { return stringName(uint32(i), rlarchStrings, true) }

// Relocation types for PowerPC.
//
// Values that are shared by both R_PPC and R_PPC64 are prefixed with
// R_POWERPC_ in the ELF standard. For the R_PPC type, the rel
"""




```