Response:
Let's break down the thought process to answer the request about the Go code snippet.

1. **Understanding the Request:** The core request is to analyze a Go code snippet defining a structure containing information about AVX instructions. Specifically, the goal is to:
    * Describe the functionality of the code.
    * Infer the larger Go feature it implements and provide an example.
    * Explain any involved command-line arguments.
    * Point out common user errors.
    * Summarize the functionality of *this specific snippet*.
    * Note that this is part 7 of 9.

2. **Initial Code Inspection:** The provided code is a series of Go struct literals. Each struct appears to have the same fields: `as`, `ytab`, `prefix`, and `op`. The values assigned to these fields look like symbolic names (e.g., `AVPMOVSDW`, `_yvpmovdw`, `Pavy`) and byte sequences (the `opBytes` struct). The `avx_optabs.go` filename strongly suggests this code defines *opcodes* or *instruction encodings* for AVX instructions.

3. **Inferring Functionality:** Based on the initial inspection, the primary function of this code is to define a data structure that maps AVX assembly instructions to their corresponding byte encodings. This is essential for a Go compiler or assembler that needs to generate machine code for AVX instructions.

4. **Inferring the Larger Go Feature:**  Given the context of instruction encodings and the file path (`go/src/cmd/internal/obj/x86/`), the most likely larger Go feature is the **assembler and compiler for the x86 architecture**. This file probably plays a role in translating Go code (or assembly code) that utilizes AVX instructions into the raw bytes that the processor understands.

5. **Constructing a Go Example:** To illustrate the use of this data, we need to imagine how the compiler/assembler would use it. The compiler would need to look up the instruction name and get the corresponding byte sequence. This suggests a lookup mechanism, perhaps using a map or by iterating through a slice. A simplified example would involve a function that takes an assembly instruction string and returns the byte representation.

6. **Considering Command-Line Arguments:**  Since this code is part of the internal workings of the Go toolchain, it's unlikely to be directly influenced by user-provided command-line arguments *at runtime of a compiled Go program*. However, the *compiler* itself has command-line arguments. Flags related to architecture (`-arch`), optimization levels, and potentially flags related to enabling/disabling specific instruction sets could indirectly influence *whether* and *how* these tables are used during the compilation process.

7. **Identifying Potential User Errors:** Direct user interaction with this file is minimal. However, when writing inline assembly or using compiler intrinsics that map to these instructions, users could make errors:
    * **Incorrect instruction names:** Typographical errors in assembly mnemonics.
    * **Incorrect operand types or order:**  AVX instructions have specific requirements for the types and order of registers and memory locations.
    * **Using instructions not supported by the target architecture:** If a user tries to use an AVX instruction on a CPU that doesn't support it.

8. **Summarizing the Snippet's Functionality:** This specific snippet focuses on defining the opcodes for a *subset* of AVX instructions, primarily those related to data movement (`PMOV`) and some arithmetic/logical operations (`PMULDQ`, `PMULHRSW`, etc.). The structure of each entry includes the assembly mnemonic (`as`), a table selector (`ytab`), a prefix (`prefix`), and the actual byte encoding (`op`). The presence of different `opBytes` within a single instruction indicates support for different AVX extensions (VEX, EVEX) and vector lengths (128, 256, 512 bits).

9. **Considering "Part 7 of 9":** This information reinforces the idea that this file is one piece of a larger system for defining AVX instruction handling. The other parts likely handle different instruction categories or other aspects of instruction encoding and decoding.

10. **Refining the Language:**  Throughout the process, focus on using clear and concise language. Explain technical terms where necessary (like "opcode," "mnemonic," "VEX/EVEX"). Structure the answer logically, addressing each part of the request.

**(Self-Correction/Refinement during the process):**

* Initially, I might have focused too narrowly on just the data movement instructions. A closer look reveals arithmetic operations as well. The summary should reflect this.
* I might have initially thought command-line arguments were irrelevant. Realizing that compiler flags *indirectly* affect this is an important refinement.
* The "ytab" field initially might seem opaque. Recognizing its role as a table selector for further encoding details is key.

By following these steps, combining code inspection with domain knowledge (compiler internals, assembly language), and iteratively refining the analysis, we can arrive at a comprehensive and accurate answer.
这段代码是Go语言编译器内部 `cmd/internal/obj` 包中，用于处理x86架构下AVX指令的一部分，具体来说，它定义了一系列AVX指令的**操作码（opcode）表**。

**功能归纳:**

这段代码的主要功能是为Go语言的x86编译器提供AVX指令的操作码信息。它将AVX汇编指令助记符（如 `AVPMOVSDW`）映射到其对应的机器码字节序列，以及相关的属性信息，例如指令的前缀、操作数类型等。这些信息是编译器在将Go代码编译成机器码时，正确编码AVX指令所必需的。

**更详细的功能分解:**

1. **定义AVX指令的操作码:**  代码中的每一个结构体 `{...}` 都代表一个AVX指令。
2. **映射汇编指令助记符:**  每个结构体的 `as` 字段存储了AVX指令的汇编助记符，例如 `AVPMOVSDW` (AVX Packed Move Signed Doubleword)。
3. **指定操作数类型表:** `ytab` 字段引用了一个操作数类型表（例如 `_yvpmovdw`），这个表定义了指令操作数的类型和布局。这部分信息不在当前代码段中，但在其他的 `_yv...` 文件中定义。
4. **定义指令前缀:** `prefix` 字段指定了指令的前缀，例如 `Pavx`，表明这是一个AVX指令。
5. **存储操作码字节序列:** `op` 字段是一个 `opBytes` 类型的结构体，包含了该指令在不同AVX扩展和向量长度下的操作码字节序列。例如，对于 `AVPMOVSDW`，它定义了在 128位、256位和 512位 EVEX 编码下的操作码和相关标志（如 `evexN8`, `evexZeroingEnabled`）。

**它是什么Go语言功能的实现？**

这段代码是Go语言**编译器**中，用于将包含AVX指令的Go代码或汇编代码转换为机器码的关键部分。更具体地说，它属于**x86架构的指令编码**模块。

**Go代码举例说明:**

虽然这段代码本身不是可以直接在Go程序中调用的函数，但它可以帮助编译器处理使用了AVX指令的代码。 假设我们有以下Go代码（需要使用 `//go:noescape` 和 `// +build !purego` 构建标签，并且需要合适的硬件支持AVX）：

```go
package main

import "unsafe"

//go:noescape
// amd64不使用purego构建
//go:linkname avx_pmovsdw runtime.avx_pmovsdw

func avx_pmovsdw(dst, src unsafe.Pointer)

func main() {
	// 假设我们有一些数据
	data1 := [4]int32{1, 2, 3, 4}
	data2 := [4]int32{0, 0, 0, 0}

	// 使用内联汇编或runtime包中的函数（此处使用go:linkname连接到runtime）
	avx_pmovsdw(unsafe.Pointer(&data2), unsafe.Pointer(&data1))

	println("Data2:", data2[0], data2[1], data2[2], data2[3])
}
```

**假设的输入与输出：**

在这个例子中，编译器在编译 `avx_pmovsdw` 函数时，会查找 `avx_optabs.go` 中关于 `AVPMOVSDW` 指令的信息。它会找到对应的操作码字节序列，并将其嵌入到最终生成的可执行文件中。

**输出:**

```
Data2: 1 2 3 4
```

**代码推理:**

`avx_pmovsdw` (Packed Move Signed Doubleword) 指令会将源操作数中的打包的带符号双字（doubleword，32位整数）移动到目标操作数。在上述例子中，`data1` 的内容被移动到了 `data2`。 `avx_optabs.go` 提供的操作码信息确保了编译器能够生成正确的机器码来执行这个移动操作。

**涉及命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。但是，Go语言编译器的命令行参数可能会间接影响这段代码的使用：

* **`-arch amd64`:**  指定目标架构为amd64（x86-64），这是使用AVX指令的前提。
* **`-gcflags "-N"`:**  禁用优化，这可能会影响内联函数的处理，但通常不直接影响操作码表的选择。
* **构建标签 (`// +build !purego`)**: 这个标签表明在非 `purego` 构建模式下编译此代码，允许使用汇编或链接到运行时包中实现的功能。

**使用者易犯错的点:**

作为编译器内部的代码，普通Go开发者不会直接修改或使用 `avx_optabs.go`。但是，当开发者尝试使用AVX指令时，可能会遇到以下错误：

* **目标架构不支持AVX:**  如果编译的目标架构不是x86-64或者CPU不支持AVX指令集，那么使用AVX指令会导致编译或运行时错误。
* **内联汇编错误:** 如果开发者直接编写内联汇编，可能会错误地使用指令助记符、操作数或编码方式，这会导致汇编器报错。
* **使用不正确的编译器/链接器选项:**  可能需要特定的构建标签或链接选项才能正确使用或链接到包含AVX指令的运行时函数。

**第7部分功能归纳:**

作为 `avx_optabs.go` 的一部分，这段代码（第7部分）具体定义了以下AVX指令的操作码：

* **数据移动指令 (PMOV):**  一系列 `AVPMOV...` 指令，用于在向量寄存器和内存之间移动打包的数据，包括带符号和无符号的转换。涵盖了不同的数据宽度（字节、字、双字、四字）和不同的 AVX 扩展（VEX, EVEX）。
* **部分条件移动指令 (PMOV** with S/Q/W/B):  `AVPMOVS...` 和 `AVPMOVUS...` 指令，根据符号位进行移动。
* **零扩展和符号扩展移动指令 (PMOVZX, PMOVSX):**  `AVPMOVZX...` 和 `AVPMOVSX...` 指令，用于在移动数据的同时进行零扩展或符号扩展。
* **存储掩码指令 (PMOVW2M):** `AVPMOVW2M` 指令，将字向量移动到掩码寄存器。
* **位操作指令 (PMOVB2M):**  在后续部分可能会出现，但当前片段中没有。
* **乘法指令 (PMULDQ, PMULHRSW, PMULHUW, PMULHW, PMULLD, PMULLQ, PMULLW, PMULTISHIFTQB, PMULUDQ):**  用于执行打包的乘法运算，包括不同类型的乘法和精度控制。
* **位计数指令 (POPCNTB, POPCNTD, POPCNTQ, POPCNTW):**  用于计算操作数中设置的位数。
* **逻辑运算指令 (POR, PORD, PORQ):**  用于执行按位或运算。
* **循环移位指令 (PROLD, PROLQ, PROLVD, PROLVQ, PRORD, PRORQ, PRORVD, PRORVQ):**  用于执行循环左移和右移操作。
* **绝对差值累加指令 (PSADBW):**  用于计算两个操作数之间的绝对差值并累加结果。
* **分散加载指令 (PSCATTERDD, PSCATTERDQ, PSCATTERQD, PSCATTERQQ):**  用于从不连续的内存位置加载数据到向量寄存器。
* **移位指令 (PSHLDD, PSHLDQ, PSHLDVD, PSHLDVQ, PSHLDW, PSHLDW,  PSHRDD,PSHRDQ,PSHRDVD,PSHRDVQ,PSHRDVW, PSHRDW,PSHUFB, PSHUFBITQMB, PSHUFD, PSHUFHW, PSHUFLW):** 用于执行各种移位操作，包括逻辑移位、算术移位和shuffle操作。
* **符号位操作指令 (PSIGNB, PSIGND, PSIGNW):**  用于根据符号位修改目标操作数的符号。
* **逻辑左移指令 (PSLLD, PSLLDQ, PSLLQ, PSLLVD, PSLLVQ, PSLLVW, PSLLW):**  用于执行逻辑左移操作。
* **算术右移指令 (PSRAD, PSRAQ, PSRAVD):**  用于执行算术右移操作。

总而言之，这段代码是Go语言编译器处理x86架构AVX指令集的核心数据结构之一，它提供了指令编码的关键信息。

### 提示词
```
这是路径为go/src/cmd/internal/obj/x86/avx_optabs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第7部分，共9部分，请归纳一下它的功能
```

### 源代码
```go
{as: AVPMOVSDW, ytab: _yvpmovdw, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x23,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x23,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x23,
	}},
	{as: AVPMOVSQB, ytab: _yvpmovdb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN2 | evexZeroingEnabled, 0x22,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x22,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x22,
	}},
	{as: AVPMOVSQD, ytab: _yvpmovdw, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x25,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x25,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x25,
	}},
	{as: AVPMOVSQW, ytab: _yvpmovdb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x24,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x24,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x24,
	}},
	{as: AVPMOVSWB, ytab: _yvpmovdw, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x20,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x20,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x20,
	}},
	{as: AVPMOVSXBD, ytab: _yvbroadcastss, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x21,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x21,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x21,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x21,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x21,
	}},
	{as: AVPMOVSXBQ, ytab: _yvbroadcastss, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x22,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x22,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN2 | evexZeroingEnabled, 0x22,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x22,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x22,
	}},
	{as: AVPMOVSXBW, ytab: _yvcvtdq2pd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x20,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x20,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x20,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x20,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x20,
	}},
	{as: AVPMOVSXDQ, ytab: _yvcvtdq2pd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x25,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x25,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x25,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x25,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x25,
	}},
	{as: AVPMOVSXWD, ytab: _yvcvtdq2pd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x23,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x23,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x23,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x23,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x23,
	}},
	{as: AVPMOVSXWQ, ytab: _yvbroadcastss, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x24,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x24,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x24,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x24,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x24,
	}},
	{as: AVPMOVUSDB, ytab: _yvpmovdb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x11,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x11,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x11,
	}},
	{as: AVPMOVUSDW, ytab: _yvpmovdw, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x13,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x13,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x13,
	}},
	{as: AVPMOVUSQB, ytab: _yvpmovdb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN2 | evexZeroingEnabled, 0x12,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x12,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x12,
	}},
	{as: AVPMOVUSQD, ytab: _yvpmovdw, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x15,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x15,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x15,
	}},
	{as: AVPMOVUSQW, ytab: _yvpmovdb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x14,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x14,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x14,
	}},
	{as: AVPMOVUSWB, ytab: _yvpmovdw, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x10,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x10,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x10,
	}},
	{as: AVPMOVW2M, ytab: _yvpmovb2m, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW1, 0, 0x29,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW1, 0, 0x29,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW1, 0, 0x29,
	}},
	{as: AVPMOVWB, ytab: _yvpmovdw, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evexF3 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x30,
		avxEscape | evex256 | evexF3 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x30,
		avxEscape | evex512 | evexF3 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x30,
	}},
	{as: AVPMOVZXBD, ytab: _yvbroadcastss, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x31,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x31,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x31,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x31,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x31,
	}},
	{as: AVPMOVZXBQ, ytab: _yvbroadcastss, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x32,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x32,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN2 | evexZeroingEnabled, 0x32,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x32,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x32,
	}},
	{as: AVPMOVZXBW, ytab: _yvcvtdq2pd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x30,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x30,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x30,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x30,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x30,
	}},
	{as: AVPMOVZXDQ, ytab: _yvcvtdq2pd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x35,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x35,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x35,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x35,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x35,
	}},
	{as: AVPMOVZXWD, ytab: _yvcvtdq2pd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x33,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x33,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x33,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x33,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x33,
	}},
	{as: AVPMOVZXWQ, ytab: _yvbroadcastss, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x34,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x34,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4 | evexZeroingEnabled, 0x34,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN8 | evexZeroingEnabled, 0x34,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x34,
	}},
	{as: AVPMULDQ, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x28,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x28,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x28,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x28,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x28,
	}},
	{as: AVPMULHRSW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x0B,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x0B,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x0B,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x0B,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x0B,
	}},
	{as: AVPMULHUW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xE4,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xE4,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xE4,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xE4,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xE4,
	}},
	{as: AVPMULHW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xE5,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xE5,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xE5,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xE5,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xE5,
	}},
	{as: AVPMULLD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x40,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x40,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x40,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x40,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x40,
	}},
	{as: AVPMULLQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x40,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x40,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x40,
	}},
	{as: AVPMULLW, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xD5,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xD5,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xD5,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0xD5,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0xD5,
	}},
	{as: AVPMULTISHIFTQB, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x83,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x83,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x83,
	}},
	{as: AVPMULUDQ, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xF4,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xF4,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xF4,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xF4,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0xF4,
	}},
	{as: AVPOPCNTB, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x54,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x54,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x54,
	}},
	{as: AVPOPCNTD, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x55,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x55,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x55,
	}},
	{as: AVPOPCNTQ, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x55,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x55,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x55,
	}},
	{as: AVPOPCNTW, ytab: _yvexpandpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexZeroingEnabled, 0x54,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexZeroingEnabled, 0x54,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexZeroingEnabled, 0x54,
	}},
	{as: AVPOR, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xEB,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xEB,
	}},
	{as: AVPORD, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0xEB,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0xEB,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0xEB,
	}},
	{as: AVPORQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0xEB,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0xEB,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0xEB,
	}},
	{as: AVPROLD, ytab: _yvprold, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x72, 01,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x72, 01,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x72, 01,
	}},
	{as: AVPROLQ, ytab: _yvprold, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x72, 01,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x72, 01,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x72, 01,
	}},
	{as: AVPROLVD, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x15,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x15,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x15,
	}},
	{as: AVPROLVQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x15,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x15,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x15,
	}},
	{as: AVPRORD, ytab: _yvprold, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x72, 00,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x72, 00,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x72, 00,
	}},
	{as: AVPRORQ, ytab: _yvprold, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x72, 00,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x72, 00,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x72, 00,
	}},
	{as: AVPRORVD, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x14,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x14,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x14,
	}},
	{as: AVPRORVQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x14,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x14,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x14,
	}},
	{as: AVPSADBW, ytab: _yvaesdec, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xF6,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xF6,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16, 0xF6,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32, 0xF6,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64, 0xF6,
	}},
	{as: AVPSCATTERDD, ytab: _yvpscatterdd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4, 0xA0,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4, 0xA0,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xA0,
	}},
	{as: AVPSCATTERDQ, ytab: _yvpscatterdq, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8, 0xA0,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8, 0xA0,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xA0,
	}},
	{as: AVPSCATTERQD, ytab: _yvpscatterqd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN4, 0xA1,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN4, 0xA1,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN4, 0xA1,
	}},
	{as: AVPSCATTERQQ, ytab: _yvpscatterdd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN8, 0xA1,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN8, 0xA1,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN8, 0xA1,
	}},
	{as: AVPSHLDD, ytab: _yvalignd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x71,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x71,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x71,
	}},
	{as: AVPSHLDQ, ytab: _yvalignd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x71,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x71,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x71,
	}},
	{as: AVPSHLDVD, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x71,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x71,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x71,
	}},
	{as: AVPSHLDVQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x71,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x71,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x71,
	}},
	{as: AVPSHLDVW, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexZeroingEnabled, 0x70,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexZeroingEnabled, 0x70,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexZeroingEnabled, 0x70,
	}},
	{as: AVPSHLDW, ytab: _yvalignd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexZeroingEnabled, 0x70,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexZeroingEnabled, 0x70,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexZeroingEnabled, 0x70,
	}},
	{as: AVPSHRDD, ytab: _yvalignd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x73,
		avxEscape | evex256 | evex66 | evex0F3A | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x73,
		avxEscape | evex512 | evex66 | evex0F3A | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x73,
	}},
	{as: AVPSHRDQ, ytab: _yvalignd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x73,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x73,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x73,
	}},
	{as: AVPSHRDVD, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x73,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x73,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x73,
	}},
	{as: AVPSHRDVQ, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x73,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x73,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x73,
	}},
	{as: AVPSHRDVW, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexZeroingEnabled, 0x72,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexZeroingEnabled, 0x72,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexZeroingEnabled, 0x72,
	}},
	{as: AVPSHRDW, ytab: _yvalignd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F3A | evexW1, evexN16 | evexZeroingEnabled, 0x72,
		avxEscape | evex256 | evex66 | evex0F3A | evexW1, evexN32 | evexZeroingEnabled, 0x72,
		avxEscape | evex512 | evex66 | evex0F3A | evexW1, evexN64 | evexZeroingEnabled, 0x72,
	}},
	{as: AVPSHUFB, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x00,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x00,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexZeroingEnabled, 0x00,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexZeroingEnabled, 0x00,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexZeroingEnabled, 0x00,
	}},
	{as: AVPSHUFBITQMB, ytab: _yvpshufbitqmb, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16, 0x8F,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32, 0x8F,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64, 0x8F,
	}},
	{as: AVPSHUFD, ytab: _yvpshufd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x70,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x70,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x70,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x70,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x70,
	}},
	{as: AVPSHUFHW, ytab: _yvpshufd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF3 | vex0F | vexW0, 0x70,
		avxEscape | vex256 | vexF3 | vex0F | vexW0, 0x70,
		avxEscape | evex128 | evexF3 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x70,
		avxEscape | evex256 | evexF3 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x70,
		avxEscape | evex512 | evexF3 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x70,
	}},
	{as: AVPSHUFLW, ytab: _yvpshufd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vexF2 | vex0F | vexW0, 0x70,
		avxEscape | vex256 | vexF2 | vex0F | vexW0, 0x70,
		avxEscape | evex128 | evexF2 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x70,
		avxEscape | evex256 | evexF2 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x70,
		avxEscape | evex512 | evexF2 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x70,
	}},
	{as: AVPSIGNB, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x08,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x08,
	}},
	{as: AVPSIGND, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x0A,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x0A,
	}},
	{as: AVPSIGNW, ytab: _yvaddsubpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x09,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x09,
	}},
	{as: AVPSLLD, ytab: _yvpslld, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x72, 06,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x72, 06,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xF2,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xF2,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x72, 06,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x72, 06,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x72, 06,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xF2,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xF2,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xF2,
	}},
	{as: AVPSLLDQ, ytab: _yvpslldq, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x73, 07,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x73, 07,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16, 0x73, 07,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32, 0x73, 07,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64, 0x73, 07,
	}},
	{as: AVPSLLQ, ytab: _yvpslld, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x73, 06,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x73, 06,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xF3,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xF3,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x73, 06,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x73, 06,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x73, 06,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0xF3,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0xF3,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0xF3,
	}},
	{as: AVPSLLVD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x47,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x47,
		avxEscape | evex128 | evex66 | evex0F38 | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x47,
		avxEscape | evex256 | evex66 | evex0F38 | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x47,
		avxEscape | evex512 | evex66 | evex0F38 | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x47,
	}},
	{as: AVPSLLVQ, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW1, 0x47,
		avxEscape | vex256 | vex66 | vex0F38 | vexW1, 0x47,
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x47,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x47,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x47,
	}},
	{as: AVPSLLVW, ytab: _yvblendmpd, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F38 | evexW1, evexN16 | evexZeroingEnabled, 0x12,
		avxEscape | evex256 | evex66 | evex0F38 | evexW1, evexN32 | evexZeroingEnabled, 0x12,
		avxEscape | evex512 | evex66 | evex0F38 | evexW1, evexN64 | evexZeroingEnabled, 0x12,
	}},
	{as: AVPSLLW, ytab: _yvpslld, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x71, 06,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x71, 06,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xF1,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xF1,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0x71, 06,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexZeroingEnabled, 0x71, 06,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexZeroingEnabled, 0x71, 06,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xF1,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xF1,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xF1,
	}},
	{as: AVPSRAD, ytab: _yvpslld, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0x72, 04,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0x72, 04,
		avxEscape | vex128 | vex66 | vex0F | vexW0, 0xE2,
		avxEscape | vex256 | vex66 | vex0F | vexW0, 0xE2,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexBcstN4 | evexZeroingEnabled, 0x72, 04,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN32 | evexBcstN4 | evexZeroingEnabled, 0x72, 04,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN64 | evexBcstN4 | evexZeroingEnabled, 0x72, 04,
		avxEscape | evex128 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xE2,
		avxEscape | evex256 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xE2,
		avxEscape | evex512 | evex66 | evex0F | evexW0, evexN16 | evexZeroingEnabled, 0xE2,
	}},
	{as: AVPSRAQ, ytab: _yvpsraq, prefix: Pavx, op: opBytes{
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexBcstN8 | evexZeroingEnabled, 0x72, 04,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN32 | evexBcstN8 | evexZeroingEnabled, 0x72, 04,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN64 | evexBcstN8 | evexZeroingEnabled, 0x72, 04,
		avxEscape | evex128 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0xE2,
		avxEscape | evex256 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0xE2,
		avxEscape | evex512 | evex66 | evex0F | evexW1, evexN16 | evexZeroingEnabled, 0xE2,
	}},
	{as: AVPSRAVD, ytab: _yvandnpd, prefix: Pavx, op: opBytes{
		avxEscape | vex128 | vex66 | vex0F38 | vexW0, 0x46,
		avxEscape | vex256 | vex66 | vex0F38 | vexW0, 0x46,
		avxEscape | evex128 | evex66 | e
```