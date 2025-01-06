Response: My goal is to analyze the provided Go code snippet and fulfill the user's request. Here's a breakdown of the thinking process:

1. **Understand the Context:** The user has provided a snippet of Go code from `go/src/cmd/internal/obj/ppc64/asm9.go`. The path strongly suggests this code is part of the Go compiler's backend for the ppc64 architecture. The comments at the beginning mentioning `cmd/9l/optab.c` and `cmd/9l/asmout.c` further indicate this is related to instruction encoding and assembly.

2. **Identify the Core Functionality:**  The code defines a struct called `Optab` and several related data structures like `ctxt9`, constants, and global variables (`optab`, `optabBase`, `prefixableOptab`, `oprange`). The comments within the code provide valuable clues. Keywords like "instruction layout," "operand combinations," and the `asmout` field in `Optab` point to this code's role in defining and managing the instruction set of the ppc64 architecture for the Go assembler.

3. **Break Down the Key Components:**

    * **`Optab` struct:**  This is clearly the central piece. Each `Optab` instance seems to represent a valid way to encode a specific ppc64 instruction. The fields like `as` (opcode), `a1` to `a6` (operand types), `type_` (internal classification), `size` (instruction size), `ispfx` (prefix instruction flag), and `asmout` (function to handle assembly) are crucial for encoding.

    * **Constants:** The `r0iszero`, `PFX_R_ABS`, `PFX_R_PCREL`, and `NOP` constants define important architecture-specific values.

    * **`ctxt9` struct:** This struct holds the state for assembling a single function. It acts as a context for the assembly process.

    * **Global Variables (`optab`, `optabBase`, `prefixableOptab`, `oprange`):**
        * `optabBase`:  Likely contains the fundamental instruction encodings.
        * `optabGen`:  While not present in this snippet, the comment suggests it exists and contributes to the `optab`.
        * `prefixableOptab`:  Deals with instructions that can be encoded differently depending on whether prefix instructions are supported (for newer architectures). This is a key optimization.
        * `optab`: The combined and sorted table of all possible instruction encodings.
        * `oprange`: An indexed structure to quickly find the valid `Optab` entries for a given opcode.

4. **Infer Go Language Feature Implementation:** Based on the identified functionality, this code is clearly part of the **Go assembler's implementation for the ppc64 architecture.** It's responsible for:
    * **Instruction Definition:** Representing the available ppc64 instructions and their valid operand combinations.
    * **Instruction Selection:** Choosing the correct instruction encoding based on the operands provided in the Go assembly code.
    * **Instruction Encoding:**  The `asmout` function (and related logic) will eventually translate the selected `Optab` entry into the actual machine code bytes.
    * **Optimization:** The `prefixableOptab` indicates an effort to leverage newer ppc64 features (prefix instructions) for better code generation on supported processors.

5. **Construct a Go Code Example:** To illustrate, a simple Go assembly function can be used. The assembler needs to determine the correct machine code for the `ADD` instruction based on the operand types. The example should demonstrate different operand types to highlight the role of `Optab`.

6. **Infer Command-Line Parameter Handling (if applicable):**  While this snippet doesn't directly show command-line argument parsing, the `pfxEnabled` variable and the handling of `prefixableOptab` strongly suggest that there's likely a compiler flag (e.g., `-G` with a specific value) that controls whether prefix instructions are enabled.

7. **Identify Potential User Errors:**  Users writing Go assembly might make mistakes with operand types. Providing examples of incorrect operand combinations and explaining why they are wrong would be helpful.

8. **Summarize the Functionality:** Concisely state the main purpose of the code.

9. **Structure the Response:** Organize the findings into the requested sections: "功能", "go语言功能的实现", "代码举例说明", "命令行参数的具体处理", "使用者易犯错的点", and "归纳一下它的功能".

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  This might be directly involved in generating the final machine code bytes.
* **Correction:** While related, the `Optab` structures primarily *define* the instructions. The actual encoding is likely handled by the `asmout` function and other related code (not fully present in the snippet).
* **Initial thought:**  The command-line arguments are explicitly parsed here.
* **Correction:**  The snippet focuses on the *data structures* for instruction representation. Command-line argument handling would occur earlier in the compilation process. However, the *impact* of those arguments is evident in variables like `pfxEnabled`.
* **Considering "使用者易犯错的点":**  Initially, I thought about very low-level encoding details. However, for a Go assembly user, the most likely errors would be at the *operand type* level.

By following these steps, including the refinement process, I can arrive at the comprehensive and accurate answer provided earlier. The key is to carefully analyze the code, comments, and context to understand the purpose and interactions of its components.
好的，让我们来分析一下这段Go语言代码 `go/src/cmd/internal/obj/ppc64/asm9.go` 的第一部分。

**功能归纳:**

这段代码定义了 ppc64 架构下的指令集和指令操作数类型的映射关系，是 Go 语言编译器中负责将 ppc64 汇编指令转换为机器码的关键部分。它主要负责以下几个核心功能：

1. **定义指令操作数类型 (Operand Types):**  通过定义各种常量 (如 `C_REG`, `C_S16CON`, `C_SOREG` 等)，来表示 ppc64 指令可以接受的不同类型的操作数，例如寄存器、立即数、内存地址等。

2. **定义指令模板 (Instruction Templates):**  `Optab` 结构体定义了一个指令的模板，包含了指令的操作码 (`as`)，各个操作数的位置和类型 (`a1` 到 `a6`)，指令的内部类型 (`type_`)，指令的大小 (`size`)，以及是否是前缀指令 (`ispfx`) 等信息。

3. **存储指令信息 (Instruction Information Storage):**  `optabBase` 和 `prefixableOptab` 变量存储了预定义的指令模板信息。 `optab` 是最终合并排序后的指令模板数组。 `oprange` 则是一个索引，用于快速查找特定操作码对应的有效 `Optab` 条目。

4. **指令查找和匹配 (Instruction Lookup and Matching):**  `oplook` 函数负责根据给定的汇编指令及其操作数，在 `optab` 中查找匹配的 `Optab` 条目。

5. **指令大小计算 (Instruction Size Calculation):**  `Optab` 结构体中的 `size` 字段记录了指令的字节大小，这在后续的指令布局和代码生成中非常重要。

6. **支持前缀指令 (Prefix Instructions Support):** 通过 `prefixableOptab` 和 `pfxEnabled` 变量，代码支持 ppc64 架构中的前缀指令，这是一种优化技术，允许更灵活的寻址和操作。

7. **指令编码处理函数 (Instruction Encoding Handler):** `Optab` 结构体中的 `asmout` 字段是一个函数指针，指向实际将指令编码为机器码的函数。

8. **指令布局和代码生成准备 (Instruction Layout and Code Generation Preparation):** `span9` 函数负责遍历函数中的指令，计算每条指令的地址，并为最终的代码生成做好准备。

**go语言功能的实现:**

这段代码是 Go 语言编译器 `cmd/compile` 中负责特定目标架构 (ppc64) 汇编到机器码转换的一部分。 具体来说，它实现了编译器后端中以下关键步骤：

1. **词法分析和语法分析后的指令表示:**  编译器前端将 Go 源代码转换为中间表示，对于汇编函数，会解析成 `obj.Prog` 类型的指令链表。

2. **指令选择 (Instruction Selection):**  `oplook` 函数基于 `obj.Prog` 中指令的操作码和操作数类型，在 `optab` 中找到最合适的机器指令编码方式。

3. **指令调度和布局 (Instruction Scheduling and Layout):** `span9` 函数遍历指令链表，计算每条指令在最终代码段中的偏移量 (`Pc`)，并考虑指令对齐等问题。

4. **机器码生成 (Machine Code Generation):** 虽然这段代码本身没有直接生成机器码，但 `Optab` 中的 `asmout` 函数指针会在后续的代码生成阶段被调用，根据选定的 `Optab` 条目将指令编码为二进制机器码。

**代码举例说明:**

假设我们有以下简单的 Go 汇编代码：

```go
//go:noinline
func add(a, b int64) int64 {
	// ... 其他代码 ...
	// MOVD a(FP), R3
	// MOVD b+8(FP), R4
	// ADD R3, R4, R5
	// MOVD R5, ret+16(FP)
	// BLR
	// ... 其他代码 ...
}
```

当编译器处理 `ADD R3, R4, R5` 这条指令时，`oplook` 函数会执行以下操作 (简化描述):

**假设输入:**  一个 `obj.Prog` 结构体，其 `As` 字段为 `ppc64.AADD`，并且操作数信息如下：

* `p.From`:  `Type: obj.TYPE_REG`, `Reg: ppc64.REG_R3`
* `p.Reg`:  `ppc64.REG_R4`
* `p.To`:    `Type: obj.TYPE_REG`, `Reg: ppc64.REG_R5`

**`oplook` 函数的推理过程:**

1. **获取操作数类型:** `oplook` 首先会调用 `c.aclass` 或 `c.aclassreg` 来确定每个操作数的类型。 在这个例子中，`R3`, `R4`, `R5` 都是通用寄存器，所以它们会被分类为 `C_REG`。

2. **查找匹配的 `Optab` 条目:** `oplook` 会在 `oprange[ppc64.AADD & obj.AMask]` 中查找 `a1` 为 `C_REG`，`a2` 为 `C_REG`，`a6` 为 `C_REG` 的 `Optab` 条目。

3. **找到匹配项:**  在 `optabBase` 中，我们能找到以下 `Optab` 条目：
   ```go
   {as: AADD, a1: C_REG, a2: C_REG, a6: C_REG, type_: 2, size: 4},
   ```
   这个条目与指令 `ADD R3, R4, R5` 的操作数类型完全匹配。

4. **返回匹配的 `Optab`:** `oplook` 函数会将该 `Optab` 条目的索引存储到 `p.Optab` 中，并返回该 `Optab` 指针。

**输出:**  `oplook` 函数返回指向匹配的 `Optab` 结构体的指针。

**`span9` 函数的推理过程 (对于该 `ADD` 指令):**

1. `span9` 会调用 `c.oplook(p)` 获取该 `ADD` 指令的 `Optab` 条目。
2. 从 `Optab` 条目中获取 `size` 字段，该字段为 `4`，表示该指令占用 4 个字节。
3. 将当前指令的 PC (`p.Pc`) 设置为当前代码段的偏移量。
4. 将代码段偏移量 `pc` 增加 4。

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。命令行参数的处理通常发生在 `cmd/compile/internal/gc` 包或其他更上层的代码中。但是，`pfxEnabled` 变量的值很可能受到命令行参数的影响。

例如，可能存在一个编译器选项（类似于 `-G` 加上一个特定的数字）来控制目标处理器的架构版本，从而决定是否启用前缀指令。如果指定了支持前缀指令的架构版本，那么 `pfxEnabled` 可能会被设置为 `true`，这会影响 `prefixableOptab` 的使用和指令编码的选择。

**使用者易犯错的点:**

对于直接使用这段代码的开发者 (通常是 Go 编译器的维护者或架构移植者)，容易犯错的点可能在于：

1. **`Optab` 条目的定义错误:**  错误的操作数类型、指令大小或内部类型会导致指令匹配失败或生成错误的机器码。

2. **`oplook` 函数的逻辑错误:**  如果 `oplook` 函数的匹配逻辑有误，可能会选择错误的 `Optab` 条目，导致生成错误的指令。

3. **未考虑前缀指令的影响:**  在支持前缀指令的架构上，如果没有正确处理 `prefixableOptab`，可能会导致性能下降或指令编码错误。 例如，手动添加一个操作数类型不匹配前缀指令要求的指令。

4. **`span9` 函数中指令地址计算错误:**  错误的指令大小或对齐计算会导致指令地址错误，破坏程序的执行流程。

**总结一下它的功能:**

这段代码的核心功能是定义和管理 ppc64 架构的指令集信息，并提供指令查找和大小计算的功能，为后续的机器码生成阶段奠定基础。它是 Go 语言编译器 ppc64 后端的重要组成部分，负责将汇编指令转换为机器可以执行的二进制代码。它通过 `Optab` 结构体和相关的数据结构，清晰地描述了每条指令的构成和特性，并利用 `oplook` 函数实现了指令匹配的关键步骤。 `span9` 函数则负责指令的布局和地址计算。对于支持前缀指令的架构，这段代码也提供了相应的处理机制。

Prompt: 
```
这是路径为go/src/cmd/internal/obj/ppc64/asm9.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共3部分，请归纳一下它的功能

"""
// cmd/9l/optab.c, cmd/9l/asmout.c from Vita Nuova.
//
//	Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2008 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2008 Lucent Technologies Inc. and others
//	Portions Copyright © 2009 The Go Authors. All rights reserved.
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

package ppc64

import (
	"cmd/internal/obj"
	"cmd/internal/objabi"
	"encoding/binary"
	"fmt"
	"internal/buildcfg"
	"log"
	"math"
	"math/bits"
	"sort"
)

// ctxt9 holds state while assembling a single function.
// Each function gets a fresh ctxt9.
// This allows for multiple functions to be safely concurrently assembled.
type ctxt9 struct {
	ctxt       *obj.Link
	newprog    obj.ProgAlloc
	cursym     *obj.LSym
	autosize   int32
	instoffset int64
	pc         int64
}

// Instruction layout.

const (
	r0iszero = 1
)

const (
	// R bit option in prefixed load/store/add D-form operations
	PFX_R_ABS   = 0 // Offset is absolute
	PFX_R_PCREL = 1 // Offset is relative to PC, RA should be 0
)

const (
	// The preferred hardware nop instruction.
	NOP = 0x60000000
)

type Optab struct {
	as    obj.As // Opcode
	a1    uint8  // p.From argument (obj.Addr). p is of type obj.Prog.
	a2    uint8  // p.Reg argument (int16 Register)
	a3    uint8  // p.RestArgs[0]  (obj.AddrPos)
	a4    uint8  // p.RestArgs[1]
	a5    uint8  // p.RestARgs[2]
	a6    uint8  // p.To (obj.Addr)
	type_ int8   // cases in asmout below. E.g., 44 = st r,(ra+rb); 45 = ld (ra+rb), r
	size  int8   // Text space in bytes to lay operation

	// A prefixed instruction is generated by this opcode. This cannot be placed
	// across a 64B PC address. Opcodes should not translate to more than one
	// prefixed instruction. The prefixed instruction should be written first
	// (e.g when Optab.size > 8).
	ispfx bool

	asmout func(*ctxt9, *obj.Prog, *Optab, *[5]uint32)
}

// optab contains an array to be sliced of accepted operand combinations for an
// instruction. Unused arguments and fields are not explicitly enumerated, and
// should not be listed for clarity. Unused arguments and values should always
// assume the default value for the given type.
//
// optab does not list every valid ppc64 opcode, it enumerates representative
// operand combinations for a class of instruction.  The variable oprange indexes
// all valid ppc64 opcodes.
//
// oprange is initialized to point a slice within optab which contains the valid
// operand combinations for a given instruction.  This is initialized from buildop.
//
// Likewise, each slice of optab is dynamically sorted using the ocmp Sort interface
// to arrange entries to minimize text size of each opcode.
//
// optab is the sorted result of combining optabBase, optabGen, and prefixableOptab.
var optab []Optab

var optabBase = []Optab{
	{as: obj.ATEXT, a1: C_LOREG, a6: C_TEXTSIZE, type_: 0, size: 0},
	{as: obj.ATEXT, a1: C_LOREG, a3: C_32CON, a6: C_TEXTSIZE, type_: 0, size: 0},
	{as: obj.ATEXT, a1: C_ADDR, a6: C_TEXTSIZE, type_: 0, size: 0},
	{as: obj.ATEXT, a1: C_ADDR, a3: C_32CON, a6: C_TEXTSIZE, type_: 0, size: 0},
	/* move register */
	{as: AADD, a1: C_REG, a2: C_REG, a6: C_REG, type_: 2, size: 4},
	{as: AADD, a1: C_REG, a6: C_REG, type_: 2, size: 4},
	{as: AADD, a1: C_S16CON, a2: C_REG, a6: C_REG, type_: 4, size: 4},
	{as: AADD, a1: C_S16CON, a6: C_REG, type_: 4, size: 4},
	{as: AADD, a1: C_U16CON, a2: C_REG, a6: C_REG, type_: 22, size: 8},
	{as: AADD, a1: C_U16CON, a6: C_REG, type_: 22, size: 8},
	{as: AADDIS, a1: C_S16CON, a2: C_REG, a6: C_REG, type_: 20, size: 4},
	{as: AADDIS, a1: C_S16CON, a6: C_REG, type_: 20, size: 4},
	{as: AADDC, a1: C_REG, a2: C_REG, a6: C_REG, type_: 2, size: 4},
	{as: AADDC, a1: C_REG, a6: C_REG, type_: 2, size: 4},
	{as: AADDC, a1: C_S16CON, a2: C_REG, a6: C_REG, type_: 4, size: 4},
	{as: AADDC, a1: C_S16CON, a6: C_REG, type_: 4, size: 4},
	{as: AADDC, a1: C_32CON, a2: C_REG, a6: C_REG, type_: 22, size: 12},
	{as: AADDC, a1: C_32CON, a6: C_REG, type_: 22, size: 12},
	{as: AAND, a1: C_REG, a2: C_REG, a6: C_REG, type_: 6, size: 4}, /* logical, no literal */
	{as: AAND, a1: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: AANDCC, a1: C_REG, a2: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: AANDCC, a1: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: AANDCC, a1: C_U16CON, a6: C_REG, type_: 58, size: 4},
	{as: AANDCC, a1: C_U16CON, a2: C_REG, a6: C_REG, type_: 58, size: 4},
	{as: AANDCC, a1: C_S16CON, a6: C_REG, type_: 23, size: 8},
	{as: AANDCC, a1: C_S16CON, a2: C_REG, a6: C_REG, type_: 23, size: 8},
	{as: AANDCC, a1: C_32CON, a6: C_REG, type_: 23, size: 12},
	{as: AANDCC, a1: C_32CON, a2: C_REG, a6: C_REG, type_: 23, size: 12},
	{as: AANDISCC, a1: C_U16CON, a6: C_REG, type_: 58, size: 4},
	{as: AANDISCC, a1: C_U16CON, a2: C_REG, a6: C_REG, type_: 58, size: 4},
	{as: AMULLW, a1: C_REG, a2: C_REG, a6: C_REG, type_: 2, size: 4},
	{as: AMULLW, a1: C_REG, a6: C_REG, type_: 2, size: 4},
	{as: AMULLW, a1: C_S16CON, a2: C_REG, a6: C_REG, type_: 4, size: 4},
	{as: AMULLW, a1: C_S16CON, a6: C_REG, type_: 4, size: 4},
	{as: AMULLW, a1: C_32CON, a2: C_REG, a6: C_REG, type_: 22, size: 12},
	{as: AMULLW, a1: C_32CON, a6: C_REG, type_: 22, size: 12},
	{as: ASUBC, a1: C_REG, a2: C_REG, a6: C_REG, type_: 10, size: 4},
	{as: ASUBC, a1: C_REG, a6: C_REG, type_: 10, size: 4},
	{as: ASUBC, a1: C_REG, a3: C_S16CON, a6: C_REG, type_: 27, size: 4},
	{as: ASUBC, a1: C_REG, a3: C_32CON, a6: C_REG, type_: 28, size: 12},
	{as: AOR, a1: C_REG, a2: C_REG, a6: C_REG, type_: 6, size: 4}, /* logical, literal not cc (or/xor) */
	{as: AOR, a1: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: AOR, a1: C_U16CON, a6: C_REG, type_: 58, size: 4},
	{as: AOR, a1: C_U16CON, a2: C_REG, a6: C_REG, type_: 58, size: 4},
	{as: AOR, a1: C_S16CON, a6: C_REG, type_: 23, size: 8},
	{as: AOR, a1: C_S16CON, a2: C_REG, a6: C_REG, type_: 23, size: 8},
	{as: AOR, a1: C_U32CON, a2: C_REG, a6: C_REG, type_: 21, size: 8},
	{as: AOR, a1: C_U32CON, a6: C_REG, type_: 21, size: 8},
	{as: AOR, a1: C_32CON, a6: C_REG, type_: 23, size: 12},
	{as: AOR, a1: C_32CON, a2: C_REG, a6: C_REG, type_: 23, size: 12},
	{as: AORIS, a1: C_U16CON, a6: C_REG, type_: 58, size: 4},
	{as: AORIS, a1: C_U16CON, a2: C_REG, a6: C_REG, type_: 58, size: 4},
	{as: ADIVW, a1: C_REG, a2: C_REG, a6: C_REG, type_: 2, size: 4}, /* op r1[,r2],r3 */
	{as: ADIVW, a1: C_REG, a6: C_REG, type_: 2, size: 4},
	{as: ASUB, a1: C_REG, a2: C_REG, a6: C_REG, type_: 10, size: 4}, /* op r2[,r1],r3 */
	{as: ASUB, a1: C_REG, a6: C_REG, type_: 10, size: 4},
	{as: ASLW, a1: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: ASLW, a1: C_REG, a2: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: ASLD, a1: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: ASLD, a1: C_REG, a2: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: ASLD, a1: C_U15CON, a2: C_REG, a6: C_REG, type_: 25, size: 4},
	{as: ASLD, a1: C_U15CON, a6: C_REG, type_: 25, size: 4},
	{as: AEXTSWSLI, a1: C_U15CON, a6: C_REG, type_: 25, size: 4},
	{as: AEXTSWSLI, a1: C_U15CON, a2: C_REG, a6: C_REG, type_: 25, size: 4},
	{as: ASLW, a1: C_U15CON, a2: C_REG, a6: C_REG, type_: 57, size: 4},
	{as: ASLW, a1: C_U15CON, a6: C_REG, type_: 57, size: 4},
	{as: ASRAW, a1: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: ASRAW, a1: C_REG, a2: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: ASRAW, a1: C_U15CON, a2: C_REG, a6: C_REG, type_: 56, size: 4},
	{as: ASRAW, a1: C_U15CON, a6: C_REG, type_: 56, size: 4},
	{as: ASRAD, a1: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: ASRAD, a1: C_REG, a2: C_REG, a6: C_REG, type_: 6, size: 4},
	{as: ASRAD, a1: C_U15CON, a2: C_REG, a6: C_REG, type_: 56, size: 4},
	{as: ASRAD, a1: C_U15CON, a6: C_REG, type_: 56, size: 4},
	{as: ARLWNM, a1: C_U15CON, a2: C_REG, a3: C_32CON, a6: C_REG, type_: 63, size: 4},
	{as: ARLWNM, a1: C_U15CON, a2: C_REG, a3: C_U15CON, a4: C_U15CON, a6: C_REG, type_: 63, size: 4},
	{as: ARLWNM, a1: C_REG, a2: C_REG, a3: C_32CON, a6: C_REG, type_: 63, size: 4},
	{as: ARLWNM, a1: C_REG, a2: C_REG, a3: C_U15CON, a4: C_U15CON, a6: C_REG, type_: 63, size: 4},
	{as: ACLRLSLWI, a1: C_U15CON, a2: C_REG, a3: C_32CON, a6: C_REG, type_: 62, size: 4},
	{as: ARLDMI, a1: C_U15CON, a2: C_REG, a3: C_32CON, a6: C_REG, type_: 30, size: 4},
	{as: ARLDC, a1: C_U15CON, a2: C_REG, a3: C_32CON, a6: C_REG, type_: 29, size: 4},
	{as: ARLDC, a1: C_REG, a3: C_U8CON, a4: C_U8CON, a6: C_REG, type_: 9, size: 4},
	{as: ARLDCL, a1: C_U15CON, a2: C_REG, a3: C_32CON, a6: C_REG, type_: 29, size: 4},
	{as: ARLDCL, a1: C_REG, a2: C_REG, a3: C_32CON, a6: C_REG, type_: 14, size: 4},
	{as: ARLDICL, a1: C_REG, a2: C_REG, a3: C_32CON, a6: C_REG, type_: 14, size: 4},
	{as: ARLDICL, a1: C_U15CON, a2: C_REG, a3: C_32CON, a6: C_REG, type_: 14, size: 4},
	{as: ARLDCL, a1: C_REG, a3: C_32CON, a6: C_REG, type_: 14, size: 4},
	{as: AFADD, a1: C_FREG, a6: C_FREG, type_: 2, size: 4},
	{as: AFADD, a1: C_FREG, a2: C_FREG, a6: C_FREG, type_: 2, size: 4},
	{as: ADADDQ, a1: C_FREGP, a6: C_FREGP, type_: 2, size: 4},
	{as: ADADDQ, a1: C_FREGP, a2: C_FREGP, a6: C_FREGP, type_: 2, size: 4},
	{as: AFABS, a1: C_FREG, a6: C_FREG, type_: 33, size: 4},
	{as: AFABS, a6: C_FREG, type_: 33, size: 4},
	{as: AFMADD, a1: C_FREG, a2: C_FREG, a3: C_FREG, a6: C_FREG, type_: 34, size: 4},
	{as: AFMUL, a1: C_FREG, a6: C_FREG, type_: 32, size: 4},
	{as: AFMUL, a1: C_FREG, a2: C_FREG, a6: C_FREG, type_: 32, size: 4},
	{as: ADMULQ, a1: C_FREGP, a6: C_FREGP, type_: 32, size: 4},
	{as: ADMULQ, a1: C_FREGP, a2: C_FREGP, a6: C_FREGP, type_: 32, size: 4},

	{as: AMOVBU, a1: C_REG, a6: C_SOREG, type_: 7, size: 4},
	{as: AMOVBU, a1: C_REG, a6: C_XOREG, type_: 108, size: 4},
	{as: AMOVBU, a1: C_SOREG, a6: C_REG, type_: 8, size: 8},
	{as: AMOVBU, a1: C_XOREG, a6: C_REG, type_: 109, size: 8},

	{as: AMOVBZU, a1: C_REG, a6: C_SOREG, type_: 7, size: 4},
	{as: AMOVBZU, a1: C_REG, a6: C_XOREG, type_: 108, size: 4},
	{as: AMOVBZU, a1: C_SOREG, a6: C_REG, type_: 8, size: 4},
	{as: AMOVBZU, a1: C_XOREG, a6: C_REG, type_: 109, size: 4},

	{as: AMOVHBR, a1: C_REG, a6: C_XOREG, type_: 44, size: 4},
	{as: AMOVHBR, a1: C_XOREG, a6: C_REG, type_: 45, size: 4},

	{as: AMOVB, a1: C_SOREG, a6: C_REG, type_: 8, size: 8},
	{as: AMOVB, a1: C_XOREG, a6: C_REG, type_: 109, size: 8},
	{as: AMOVB, a1: C_REG, a6: C_SOREG, type_: 7, size: 4},
	{as: AMOVB, a1: C_REG, a6: C_XOREG, type_: 108, size: 4},
	{as: AMOVB, a1: C_REG, a6: C_REG, type_: 13, size: 4},

	{as: AMOVBZ, a1: C_SOREG, a6: C_REG, type_: 8, size: 4},
	{as: AMOVBZ, a1: C_XOREG, a6: C_REG, type_: 109, size: 4},
	{as: AMOVBZ, a1: C_REG, a6: C_SOREG, type_: 7, size: 4},
	{as: AMOVBZ, a1: C_REG, a6: C_XOREG, type_: 108, size: 4},
	{as: AMOVBZ, a1: C_REG, a6: C_REG, type_: 13, size: 4},

	{as: AMOVD, a1: C_16CON, a6: C_REG, type_: 3, size: 4},
	{as: AMOVD, a1: C_SACON, a6: C_REG, type_: 3, size: 4},
	{as: AMOVD, a1: C_SOREG, a6: C_REG, type_: 8, size: 4},
	{as: AMOVD, a1: C_XOREG, a6: C_REG, type_: 109, size: 4},
	{as: AMOVD, a1: C_SOREG, a6: C_SPR, type_: 107, size: 8},
	{as: AMOVD, a1: C_SPR, a6: C_REG, type_: 66, size: 4},
	{as: AMOVD, a1: C_REG, a6: C_SOREG, type_: 7, size: 4},
	{as: AMOVD, a1: C_REG, a6: C_XOREG, type_: 108, size: 4},
	{as: AMOVD, a1: C_SPR, a6: C_SOREG, type_: 106, size: 8},
	{as: AMOVD, a1: C_REG, a6: C_SPR, type_: 66, size: 4},
	{as: AMOVD, a1: C_REG, a6: C_REG, type_: 13, size: 4},

	{as: AMOVW, a1: C_16CON, a6: C_REG, type_: 3, size: 4},
	{as: AMOVW, a1: C_SACON, a6: C_REG, type_: 3, size: 4},
	{as: AMOVW, a1: C_CREG, a6: C_REG, type_: 68, size: 4},
	{as: AMOVW, a1: C_SOREG, a6: C_REG, type_: 8, size: 4},
	{as: AMOVW, a1: C_XOREG, a6: C_REG, type_: 109, size: 4},
	{as: AMOVW, a1: C_SPR, a6: C_REG, type_: 66, size: 4},
	{as: AMOVW, a1: C_REG, a6: C_CREG, type_: 69, size: 4},
	{as: AMOVW, a1: C_REG, a6: C_SOREG, type_: 7, size: 4},
	{as: AMOVW, a1: C_REG, a6: C_XOREG, type_: 108, size: 4},
	{as: AMOVW, a1: C_REG, a6: C_SPR, type_: 66, size: 4},
	{as: AMOVW, a1: C_REG, a6: C_REG, type_: 13, size: 4},

	{as: AFMOVD, a1: C_S16CON, a6: C_FREG, type_: 24, size: 8},
	{as: AFMOVD, a1: C_SOREG, a6: C_FREG, type_: 8, size: 4},
	{as: AFMOVD, a1: C_XOREG, a6: C_FREG, type_: 109, size: 4},
	{as: AFMOVD, a1: C_ZCON, a6: C_FREG, type_: 24, size: 4},
	{as: AFMOVD, a1: C_FREG, a6: C_FREG, type_: 33, size: 4},
	{as: AFMOVD, a1: C_FREG, a6: C_SOREG, type_: 7, size: 4},
	{as: AFMOVD, a1: C_FREG, a6: C_XOREG, type_: 108, size: 4},

	{as: AFMOVSX, a1: C_XOREG, a6: C_FREG, type_: 45, size: 4},
	{as: AFMOVSX, a1: C_FREG, a6: C_XOREG, type_: 44, size: 4},

	{as: AFMOVSZ, a1: C_ZOREG, a6: C_FREG, type_: 45, size: 4},
	{as: AFMOVSZ, a1: C_XOREG, a6: C_FREG, type_: 45, size: 4},

	{as: AMOVFL, a1: C_CREG, a6: C_CREG, type_: 67, size: 4},
	{as: AMOVFL, a1: C_FPSCR, a6: C_CREG, type_: 73, size: 4},
	{as: AMOVFL, a1: C_FPSCR, a6: C_FREG, type_: 53, size: 4},
	{as: AMOVFL, a1: C_FREG, a3: C_32CON, a6: C_FPSCR, type_: 64, size: 4},
	{as: AMOVFL, a1: C_FREG, a6: C_FPSCR, type_: 64, size: 4},
	{as: AMOVFL, a1: C_32CON, a6: C_FPSCR, type_: 65, size: 4},
	{as: AMOVFL, a1: C_REG, a6: C_CREG, type_: 69, size: 4},
	{as: AMOVFL, a1: C_REG, a6: C_32CON, type_: 69, size: 4},

	{as: ASYSCALL, type_: 5, size: 4},
	{as: ASYSCALL, a1: C_REG, type_: 77, size: 12},
	{as: ASYSCALL, a1: C_U15CON, type_: 77, size: 12},
	{as: ABEQ, a6: C_BRA, type_: 16, size: 4},
	{as: ABEQ, a1: C_CREG, a6: C_BRA, type_: 16, size: 4},
	{as: ABEQ, a1: C_CREG, a6: C_LR, type_: 17, size: 4},
	{as: ABR, a6: C_BRA, type_: 11, size: 4},                                         // b label
	{as: ABR, a6: C_BRAPIC, type_: 11, size: 8},                                      // b label; nop
	{as: ABR, a6: C_LR, type_: 18, size: 4},                                          // blr
	{as: ABR, a6: C_CTR, type_: 18, size: 4},                                         // bctr
	{as: ABC, a1: C_U15CON, a2: C_CRBIT, a6: C_BRA, type_: 16, size: 4},              // bc bo, bi, label
	{as: ABC, a1: C_U15CON, a2: C_CRBIT, a6: C_LR, type_: 18, size: 4},               // bclr bo, bi
	{as: ABC, a1: C_U15CON, a2: C_CRBIT, a3: C_U15CON, a6: C_LR, type_: 18, size: 4}, // bclr bo, bi, bh
	{as: ABC, a1: C_U15CON, a2: C_CRBIT, a6: C_CTR, type_: 18, size: 4},              // bcctr bo, bi
	{as: ABDNZ, a6: C_BRA, type_: 16, size: 4},
	{as: ASYNC, type_: 46, size: 4},
	{as: AWORD, a1: C_32CON, type_: 40, size: 4},
	{as: ADWORD, a1: C_64CON, type_: 31, size: 8},
	{as: ADWORD, a1: C_LACON, type_: 31, size: 8},
	{as: AADDME, a1: C_REG, a6: C_REG, type_: 47, size: 4},
	{as: AEXTSB, a1: C_REG, a6: C_REG, type_: 48, size: 4},
	{as: AEXTSB, a6: C_REG, type_: 48, size: 4},
	{as: AISEL, a1: C_U5CON, a2: C_REG, a3: C_REG, a6: C_REG, type_: 84, size: 4},
	{as: AISEL, a1: C_CRBIT, a2: C_REG, a3: C_REG, a6: C_REG, type_: 84, size: 4},
	{as: ANEG, a1: C_REG, a6: C_REG, type_: 47, size: 4},
	{as: ANEG, a6: C_REG, type_: 47, size: 4},
	{as: AREM, a1: C_REG, a6: C_REG, type_: 50, size: 12},
	{as: AREM, a1: C_REG, a2: C_REG, a6: C_REG, type_: 50, size: 12},
	{as: AREMU, a1: C_REG, a6: C_REG, type_: 50, size: 16},
	{as: AREMU, a1: C_REG, a2: C_REG, a6: C_REG, type_: 50, size: 16},
	{as: AREMD, a1: C_REG, a6: C_REG, type_: 51, size: 12},
	{as: AREMD, a1: C_REG, a2: C_REG, a6: C_REG, type_: 51, size: 12},
	{as: AMTFSB0, a1: C_U15CON, type_: 52, size: 4},
	/* Other ISA 2.05+ instructions */
	{as: APOPCNTD, a1: C_REG, a6: C_REG, type_: 93, size: 4},            /* population count, x-form */
	{as: ACMPB, a1: C_REG, a2: C_REG, a6: C_REG, type_: 92, size: 4},    /* compare byte, x-form */
	{as: ACMPEQB, a1: C_REG, a2: C_REG, a6: C_CREG, type_: 92, size: 4}, /* compare equal byte, x-form, ISA 3.0 */
	{as: ACMPEQB, a1: C_REG, a6: C_REG, type_: 70, size: 4},
	{as: AFTDIV, a1: C_FREG, a2: C_FREG, a6: C_U15CON, type_: 92, size: 4},          /* floating test for sw divide, x-form */
	{as: AFTSQRT, a1: C_FREG, a6: C_U15CON, type_: 93, size: 4},                     /* floating test for sw square root, x-form */
	{as: ACOPY, a1: C_REG, a6: C_REG, type_: 92, size: 4},                           /* copy/paste facility, x-form */
	{as: ADARN, a1: C_U15CON, a6: C_REG, type_: 92, size: 4},                        /* deliver random number, x-form */
	{as: AMADDHD, a1: C_REG, a2: C_REG, a3: C_REG, a6: C_REG, type_: 83, size: 4},   /* multiply-add high/low doubleword, va-form */
	{as: AADDEX, a1: C_REG, a2: C_REG, a3: C_U15CON, a6: C_REG, type_: 94, size: 4}, /* add extended using alternate carry, z23-form */
	{as: ACRAND, a1: C_CRBIT, a2: C_CRBIT, a6: C_CRBIT, type_: 2, size: 4},          /* logical ops for condition register bits xl-form */

	/* Misc ISA 3.0 instructions */
	{as: ASETB, a1: C_CREG, a6: C_REG, type_: 110, size: 4},
	{as: AVCLZLSBB, a1: C_VREG, a6: C_REG, type_: 85, size: 4},

	/* Vector instructions */

	/* Vector load */
	{as: ALVEBX, a1: C_XOREG, a6: C_VREG, type_: 45, size: 4}, /* vector load, x-form */

	/* Vector store */
	{as: ASTVEBX, a1: C_VREG, a6: C_XOREG, type_: 44, size: 4}, /* vector store, x-form */

	/* Vector logical */
	{as: AVAND, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4}, /* vector and, vx-form */
	{as: AVOR, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},  /* vector or, vx-form */

	/* Vector add */
	{as: AVADDUM, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},            /* vector add unsigned modulo, vx-form */
	{as: AVADDCU, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},            /* vector add & write carry unsigned, vx-form */
	{as: AVADDUS, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},            /* vector add unsigned saturate, vx-form */
	{as: AVADDSS, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},            /* vector add signed saturate, vx-form */
	{as: AVADDE, a1: C_VREG, a2: C_VREG, a3: C_VREG, a6: C_VREG, type_: 83, size: 4}, /* vector add extended, va-form */

	/* Vector subtract */
	{as: AVSUBUM, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},            /* vector subtract unsigned modulo, vx-form */
	{as: AVSUBCU, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},            /* vector subtract & write carry unsigned, vx-form */
	{as: AVSUBUS, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},            /* vector subtract unsigned saturate, vx-form */
	{as: AVSUBSS, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},            /* vector subtract signed saturate, vx-form */
	{as: AVSUBE, a1: C_VREG, a2: C_VREG, a3: C_VREG, a6: C_VREG, type_: 83, size: 4}, /* vector subtract extended, va-form */

	/* Vector multiply */
	{as: AVMULESB, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},              /* vector multiply, vx-form */
	{as: AVPMSUM, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},               /* vector polynomial multiply & sum, vx-form */
	{as: AVMSUMUDM, a1: C_VREG, a2: C_VREG, a3: C_VREG, a6: C_VREG, type_: 83, size: 4}, /* vector multiply-sum, va-form */

	/* Vector rotate */
	{as: AVR, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4}, /* vector rotate, vx-form */

	/* Vector shift */
	{as: AVS, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},                 /* vector shift, vx-form */
	{as: AVSA, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},                /* vector shift algebraic, vx-form */
	{as: AVSOI, a1: C_U16CON, a2: C_VREG, a3: C_VREG, a6: C_VREG, type_: 83, size: 4}, /* vector shift by octet immediate, va-form */

	/* Vector count */
	{as: AVCLZ, a1: C_VREG, a6: C_VREG, type_: 85, size: 4},    /* vector count leading zeros, vx-form */
	{as: AVPOPCNT, a1: C_VREG, a6: C_VREG, type_: 85, size: 4}, /* vector population count, vx-form */

	/* Vector compare */
	{as: AVCMPEQ, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},   /* vector compare equal, vc-form */
	{as: AVCMPGT, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},   /* vector compare greater than, vc-form */
	{as: AVCMPNEZB, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4}, /* vector compare not equal, vx-form */

	/* Vector merge */
	{as: AVMRGOW, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4}, /* vector merge odd word, vx-form */

	/* Vector permute */
	{as: AVPERM, a1: C_VREG, a2: C_VREG, a3: C_VREG, a6: C_VREG, type_: 83, size: 4}, /* vector permute, va-form */

	/* Vector bit permute */
	{as: AVBPERMQ, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4}, /* vector bit permute, vx-form */

	/* Vector select */
	{as: AVSEL, a1: C_VREG, a2: C_VREG, a3: C_VREG, a6: C_VREG, type_: 83, size: 4}, /* vector select, va-form */

	/* Vector splat */
	{as: AVSPLTB, a1: C_S16CON, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},
	{as: AVSPLTISB, a1: C_S16CON, a6: C_VREG, type_: 82, size: 4},

	/* Vector AES */
	{as: AVCIPH, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4},  /* vector AES cipher, vx-form */
	{as: AVNCIPH, a1: C_VREG, a2: C_VREG, a6: C_VREG, type_: 82, size: 4}, /* vector AES inverse cipher, vx-form */
	{as: AVSBOX, a1: C_VREG, a6: C_VREG, type_: 82, size: 4},              /* vector AES subbytes, vx-form */

	/* Vector SHA */
	{as: AVSHASIGMA, a1: C_U16CON, a2: C_VREG, a3: C_U16CON, a6: C_VREG, type_: 82, size: 4}, /* vector SHA sigma, vx-form */

	/* VSX vector load */
	{as: ALXVD2X, a1: C_XOREG, a6: C_VSREG, type_: 87, size: 4},        /* vsx vector load, xx1-form */
	{as: ALXV, a1: C_SOREG, a6: C_VSREG, type_: 96, size: 4},           /* vsx vector load, dq-form */
	{as: ALXVL, a1: C_REG, a2: C_REG, a6: C_VSREG, type_: 98, size: 4}, /* vsx vector load length */

	/* VSX vector store */
	{as: ASTXVD2X, a1: C_VSREG, a6: C_XOREG, type_: 86, size: 4},        /* vsx vector store, xx1-form */
	{as: ASTXV, a1: C_VSREG, a6: C_SOREG, type_: 97, size: 4},           /* vsx vector store, dq-form */
	{as: ASTXVL, a1: C_VSREG, a2: C_REG, a6: C_REG, type_: 99, size: 4}, /* vsx vector store with length x-form */

	/* VSX scalar load */
	{as: ALXSDX, a1: C_XOREG, a6: C_VSREG, type_: 87, size: 4}, /* vsx scalar load, xx1-form */

	/* VSX scalar store */
	{as: ASTXSDX, a1: C_VSREG, a6: C_XOREG, type_: 86, size: 4}, /* vsx scalar store, xx1-form */

	/* VSX scalar as integer load */
	{as: ALXSIWAX, a1: C_XOREG, a6: C_VSREG, type_: 87, size: 4}, /* vsx scalar as integer load, xx1-form */

	/* VSX scalar store as integer */
	{as: ASTXSIWX, a1: C_VSREG, a6: C_XOREG, type_: 86, size: 4}, /* vsx scalar as integer store, xx1-form */

	/* VSX move from VSR */
	{as: AMFVSRD, a1: C_VSREG, a6: C_REG, type_: 88, size: 4},
	{as: AMFVSRD, a1: C_FREG, a6: C_REG, type_: 88, size: 4},

	/* VSX move to VSR */
	{as: AMTVSRD, a1: C_REG, a6: C_VSREG, type_: 104, size: 4},
	{as: AMTVSRD, a1: C_REG, a6: C_FREG, type_: 104, size: 4},
	{as: AMTVSRDD, a1: C_REG, a2: C_REG, a6: C_VSREG, type_: 104, size: 4},

	/* VSX xx3-form */
	{as: AXXLAND, a1: C_FREG, a2: C_FREG, a6: C_FREG, type_: 90, size: 4},    /* vsx xx3-form (FPR usage) */
	{as: AXXLAND, a1: C_VSREG, a2: C_VSREG, a6: C_VSREG, type_: 90, size: 4}, /* vsx xx3-form */

	/* VSX select */
	{as: AXXSEL, a1: C_VSREG, a2: C_VSREG, a3: C_VSREG, a6: C_VSREG, type_: 91, size: 4}, /* vsx select, xx4-form */

	/* VSX merge */
	{as: AXXMRGHW, a1: C_VSREG, a2: C_VSREG, a6: C_VSREG, type_: 90, size: 4}, /* vsx merge, xx3-form */

	/* VSX splat */
	{as: AXXSPLTW, a1: C_VSREG, a3: C_U15CON, a6: C_VSREG, type_: 89, size: 4}, /* vsx splat, xx2-form */
	{as: AXXSPLTIB, a1: C_U15CON, a6: C_VSREG, type_: 100, size: 4},            /* vsx splat, xx2-form */

	/* VSX permute */
	{as: AXXPERM, a1: C_VSREG, a2: C_VSREG, a6: C_VSREG, type_: 90, size: 4}, /* vsx permute, xx3-form */

	/* VSX shift */
	{as: AXXSLDWI, a1: C_VSREG, a2: C_VSREG, a3: C_U15CON, a6: C_VSREG, type_: 90, size: 4}, /* vsx shift immediate, xx3-form */

	/* VSX reverse bytes */
	{as: AXXBRQ, a1: C_VSREG, a6: C_VSREG, type_: 101, size: 4}, /* vsx reverse bytes */

	/* VSX scalar FP-FP conversion */
	{as: AXSCVDPSP, a1: C_VSREG, a6: C_VSREG, type_: 89, size: 4}, /* vsx scalar fp-fp conversion, xx2-form */

	/* VSX vector FP-FP conversion */
	{as: AXVCVDPSP, a1: C_VSREG, a6: C_VSREG, type_: 89, size: 4}, /* vsx vector fp-fp conversion, xx2-form */

	/* VSX scalar FP-integer conversion */
	{as: AXSCVDPSXDS, a1: C_VSREG, a6: C_VSREG, type_: 89, size: 4}, /* vsx scalar fp-integer conversion, xx2-form */

	/* VSX scalar integer-FP conversion */
	{as: AXSCVSXDDP, a1: C_VSREG, a6: C_VSREG, type_: 89, size: 4}, /* vsx scalar integer-fp conversion, xx2-form */

	/* VSX vector FP-integer conversion */
	{as: AXVCVDPSXDS, a1: C_VSREG, a6: C_VSREG, type_: 89, size: 4}, /* vsx vector fp-integer conversion, xx2-form */

	/* VSX vector integer-FP conversion */
	{as: AXVCVSXDDP, a1: C_VSREG, a6: C_VSREG, type_: 89, size: 4}, /* vsx vector integer-fp conversion, xx2-form */

	{as: ACMP, a1: C_REG, a6: C_REG, type_: 70, size: 4},
	{as: ACMP, a1: C_REG, a2: C_CREG, a6: C_REG, type_: 70, size: 4},
	{as: ACMP, a1: C_REG, a6: C_S16CON, type_: 70, size: 4},
	{as: ACMP, a1: C_REG, a2: C_CREG, a6: C_S16CON, type_: 70, size: 4},
	{as: ACMPU, a1: C_REG, a6: C_REG, type_: 70, size: 4},
	{as: ACMPU, a1: C_REG, a2: C_CREG, a6: C_REG, type_: 70, size: 4},
	{as: ACMPU, a1: C_REG, a6: C_U16CON, type_: 70, size: 4},
	{as: ACMPU, a1: C_REG, a2: C_CREG, a6: C_U16CON, type_: 70, size: 4},
	{as: AFCMPO, a1: C_FREG, a6: C_FREG, type_: 70, size: 4},
	{as: AFCMPO, a1: C_FREG, a2: C_CREG, a6: C_FREG, type_: 70, size: 4},
	{as: ADCMPOQ, a1: C_FREGP, a6: C_FREGP, type_: 70, size: 4},
	{as: ADCMPOQ, a1: C_FREGP, a2: C_CREG, a6: C_FREGP, type_: 70, size: 4},
	{as: ATW, a1: C_32CON, a2: C_REG, a6: C_REG, type_: 60, size: 4},
	{as: ATW, a1: C_32CON, a2: C_REG, a6: C_S16CON, type_: 61, size: 4},
	{as: ADCBF, a1: C_SOREG, type_: 43, size: 4},
	{as: ADCBF, a1: C_XOREG, type_: 43, size: 4},
	{as: ADCBF, a1: C_XOREG, a2: C_REG, a6: C_U15CON, type_: 43, size: 4},
	{as: ADCBF, a1: C_SOREG, a6: C_U15CON, type_: 43, size: 4},
	{as: ADCBF, a1: C_XOREG, a6: C_U15CON, type_: 43, size: 4},
	{as: ASTDCCC, a1: C_REG, a2: C_REG, a6: C_XOREG, type_: 44, size: 4},
	{as: ASTDCCC, a1: C_REG, a6: C_XOREG, type_: 44, size: 4},
	{as: ALDAR, a1: C_XOREG, a6: C_REG, type_: 45, size: 4},
	{as: ALDAR, a1: C_XOREG, a3: C_U16CON, a6: C_REG, type_: 45, size: 4},
	{as: AEIEIO, type_: 46, size: 4},
	{as: ATLBIE, a1: C_REG, type_: 49, size: 4},
	{as: ATLBIE, a1: C_U15CON, a6: C_REG, type_: 49, size: 4},
	{as: ASLBMFEE, a1: C_REG, a6: C_REG, type_: 55, size: 4},
	{as: ASLBMTE, a1: C_REG, a6: C_REG, type_: 55, size: 4},
	{as: ASTSW, a1: C_REG, a6: C_XOREG, type_: 44, size: 4},
	{as: ASTSW, a1: C_REG, a3: C_32CON, a6: C_ZOREG, type_: 41, size: 4},
	{as: ALSW, a1: C_XOREG, a6: C_REG, type_: 45, size: 4},
	{as: ALSW, a1: C_ZOREG, a3: C_32CON, a6: C_REG, type_: 42, size: 4},

	{as: obj.AUNDEF, type_: 78, size: 4},
	{as: obj.APCDATA, a1: C_32CON, a6: C_32CON, type_: 0, size: 0},
	{as: obj.AFUNCDATA, a1: C_U15CON, a6: C_ADDR, type_: 0, size: 0},
	{as: obj.ANOP, type_: 0, size: 0},
	{as: obj.ANOP, a1: C_32CON, type_: 0, size: 0}, // NOP operand variations added for #40689
	{as: obj.ANOP, a1: C_REG, type_: 0, size: 0},   // to preserve previous behavior
	{as: obj.ANOP, a1: C_FREG, type_: 0, size: 0},
	{as: obj.ADUFFZERO, a6: C_BRA, type_: 11, size: 4}, // same as ABR/ABL
	{as: obj.ADUFFCOPY, a6: C_BRA, type_: 11, size: 4}, // same as ABR/ABL
	{as: obj.APCALIGN, a1: C_32CON, type_: 0, size: 0}, // align code
}

// These are opcodes above which may generate different sequences depending on whether prefix opcode support
// is available
type PrefixableOptab struct {
	Optab
	minGOPPC64 int  // Minimum GOPPC64 required to support this.
	pfxsize    int8 // Instruction sequence size when prefixed opcodes are used
}

// The prefixable optab entry contains the pseudo-opcodes which generate relocations, or may generate
// a more efficient sequence of instructions if a prefixed version exists (ex. paddi instead of oris/ori/add).
//
// This table is meant to transform all sequences which might be TOC-relative into an equivalent PC-relative
// sequence. It also encompasses several transformations which do not involve relocations, those could be
// separated and applied to AIX and other non-ELF targets. Likewise, the prefixed forms do not have encoding
// restrictions on the offset, so they are also used for static binary to allow better code generation. e.x
//
//	MOVD something-byte-aligned(Rx), Ry
//	MOVD 3(Rx), Ry
//
// is allowed when the prefixed forms are used.
//
// This requires an ISA 3.1 compatible cpu (e.g Power10), and when linking externally an ELFv2 1.5 compliant.
var prefixableOptab = []PrefixableOptab{
	{Optab: Optab{as: AMOVD, a1: C_S34CON, a6: C_REG, type_: 19, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVD, a1: C_ADDR, a6: C_REG, type_: 75, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVD, a1: C_TLS_LE, a6: C_REG, type_: 79, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVD, a1: C_TLS_IE, a6: C_REG, type_: 80, size: 12}, minGOPPC64: 10, pfxsize: 12},
	{Optab: Optab{as: AMOVD, a1: C_LACON, a6: C_REG, type_: 26, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVD, a1: C_LOREG, a6: C_REG, type_: 36, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVD, a1: C_REG, a6: C_LOREG, type_: 35, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVD, a1: C_REG, a6: C_ADDR, type_: 74, size: 8}, minGOPPC64: 10, pfxsize: 8},

	{Optab: Optab{as: AMOVW, a1: C_32CON, a6: C_REG, type_: 19, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVW, a1: C_LACON, a6: C_REG, type_: 26, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVW, a1: C_LOREG, a6: C_REG, type_: 36, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVW, a1: C_ADDR, a6: C_REG, type_: 75, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVW, a1: C_REG, a6: C_LOREG, type_: 35, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVW, a1: C_REG, a6: C_ADDR, type_: 74, size: 8}, minGOPPC64: 10, pfxsize: 8},

	{Optab: Optab{as: AMOVB, a1: C_REG, a6: C_LOREG, type_: 35, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVB, a1: C_LOREG, a6: C_REG, type_: 36, size: 12}, minGOPPC64: 10, pfxsize: 12},
	{Optab: Optab{as: AMOVB, a1: C_ADDR, a6: C_REG, type_: 75, size: 12}, minGOPPC64: 10, pfxsize: 12},
	{Optab: Optab{as: AMOVB, a1: C_REG, a6: C_ADDR, type_: 74, size: 8}, minGOPPC64: 10, pfxsize: 8},

	{Optab: Optab{as: AMOVBZ, a1: C_LOREG, a6: C_REG, type_: 36, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVBZ, a1: C_ADDR, a6: C_REG, type_: 75, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVBZ, a1: C_REG, a6: C_LOREG, type_: 35, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AMOVBZ, a1: C_REG, a6: C_ADDR, type_: 74, size: 8}, minGOPPC64: 10, pfxsize: 8},

	{Optab: Optab{as: AFMOVD, a1: C_LOREG, a6: C_FREG, type_: 36, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AFMOVD, a1: C_ADDR, a6: C_FREG, type_: 75, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AFMOVD, a1: C_FREG, a6: C_LOREG, type_: 35, size: 8}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AFMOVD, a1: C_FREG, a6: C_ADDR, type_: 74, size: 8}, minGOPPC64: 10, pfxsize: 8},

	{Optab: Optab{as: AADD, a1: C_32CON, a2: C_REG, a6: C_REG, type_: 22, size: 12}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AADD, a1: C_32CON, a6: C_REG, type_: 22, size: 12}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AADD, a1: C_S34CON, a2: C_REG, a6: C_REG, type_: 22, size: 20}, minGOPPC64: 10, pfxsize: 8},
	{Optab: Optab{as: AADD, a1: C_S34CON, a6: C_REG, type_: 22, size: 20}, minGOPPC64: 10, pfxsize: 8},
}

var oprange [ALAST & obj.AMask][]Optab

var xcmp [C_NCLASS][C_NCLASS]bool

var pfxEnabled = false // ISA 3.1 prefixed instructions are supported.
var buildOpCfg = ""    // Save the os/cpu/arch tuple used to configure the assembler in buildop

// padding bytes to add to align code as requested.
func addpad(pc, a int64, ctxt *obj.Link, cursym *obj.LSym) int {
	switch a {
	case 8, 16, 32, 64:
		// By default function alignment is 16. If an alignment > 16 is
		// requested then the function alignment must also be promoted.
		// The function alignment is not promoted on AIX at this time.
		// TODO: Investigate AIX function alignment.
		if ctxt.Headtype != objabi.Haix && cursym.Func().Align < int32(a) {
			cursym.Func().Align = int32(a)
		}
		if pc&(a-1) != 0 {
			return int(a - (pc & (a - 1)))
		}
	default:
		ctxt.Diag("Unexpected alignment: %d for PCALIGN directive\n", a)
	}
	return 0
}

func span9(ctxt *obj.Link, cursym *obj.LSym, newprog obj.ProgAlloc) {
	p := cursym.Func().Text
	if p == nil || p.Link == nil { // handle external functions and ELF section symbols
		return
	}

	if oprange[AANDN&obj.AMask] == nil {
		ctxt.Diag("ppc64 ops not initialized, call ppc64.buildop first")
	}

	c := ctxt9{ctxt: ctxt, newprog: newprog, cursym: cursym, autosize: int32(p.To.Offset)}

	pc := int64(0)
	p.Pc = pc

	var m int
	var o *Optab
	for p = p.Link; p != nil; p = p.Link {
		p.Pc = pc
		o = c.oplook(p)
		m = int(o.size)
		if m == 0 {
			if p.As == obj.APCALIGN {
				a := c.vregoff(&p.From)
				m = addpad(pc, a, ctxt, cursym)
			} else {
				if p.As != obj.ANOP && p.As != obj.AFUNCDATA && p.As != obj.APCDATA {
					ctxt.Diag("zero-width instruction\n%v", p)
				}
				continue
			}
		}
		pc += int64(m)
	}

	c.cursym.Size = pc

	/*
	 * if any procedure is large enough to
	 * generate a large SBRA branch, then
	 * generate extra passes putting branches
	 * around jmps to fix. this is rare.
	 */
	bflag := 1

	var otxt int64
	var q *obj.Prog
	var out [5]uint32
	var falign int32 // Track increased alignment requirements for prefix.
	for bflag != 0 {
		bflag = 0
		pc = 0
		falign = 0 // Note, linker bumps function symbols to funcAlign.
		for p = c.cursym.Func().Text.Link; p != nil; p = p.Link {
			p.Pc = pc
			o = c.oplook(p)

			// very large conditional branches
			if (o.type_ == 16 || o.type_ == 17) && p.To.Target() != nil {
				otxt = p.To.Target().Pc - pc
				if otxt < -(1<<15)+10 || otxt >= (1<<15)-10 {
					// Assemble the instruction with a target not too far to figure out BI and BO fields.
					// If only the CTR or BI (the CR bit) are tested, the conditional branch can be inverted,
					// and only one extra branch is needed to reach the target.
					tgt := p.To.Target()
					p.To.SetTarget(p.Link)
					o.asmout(&c, p, o, &out)
					p.To.SetTarget(tgt)

					bo := int64(out[0]>>21) & 31
					bi := int16((out[0] >> 16) & 31)
					invertible := false

					if bo&0x14 == 0x14 {
						// A conditional branch that is unconditionally taken. This cannot be inverted.
					} else if bo&0x10 == 0x10 {
						// A branch based on the value of CTR. Invert the CTR comparison against zero bit.
						bo ^= 0x2
						invertible = true
					} else if bo&0x04 == 0x04 {
						// A branch based on CR bit. Invert the BI comparison bit.
						bo ^= 0x8
						invertible = true
					}

					if invertible {
						// Rewrite
						//     BC bo,...,far_away_target
						//     NEXT_INSN
						// to:
						//     BC invert(bo),next_insn
						//     JMP far_away_target
						//   next_insn:
						//     NEXT_INSN
						p.As = ABC
						p.From = obj.Addr{Type: obj.TYPE_CONST, Name: obj.NAME_NONE, Offset: bo}
						q = c.newprog()
						q.As = ABR
						q.To.Type = obj.TYPE_BRANCH
						q.To.SetTarget(p.To.Target())
						q.Link = p.Link
						p.To.SetTarget(p.Link)
						p.Link = q
						p.Reg = REG_CRBIT0 + bi
					} else {
						// Rewrite
						//     BC ...,far_away_target
						//     NEXT_INSN
						// to
						//     BC ...,tmp
						//     JMP next_insn
						//   tmp:
						//     JMP far_away_target
						//   next_insn:
						//     NEXT_INSN
						q = c.newprog()
						q.Link = p.Link
						p.Link = q
						q.As = ABR
						q.To.Type = obj.TYPE_BRANCH
						q.To.SetTarget(p.To.Target())
						p.To.SetTarget(q)
						q = c.newprog()
						q.Link = p.Link
						p.Link = q
						q.As = ABR
						q.To.Type = obj.TYPE_BRANCH
						q.To.SetTarget(q.Link.Link)
					}
					bflag = 1
				}
			}

			m = int(o.size)
			if m == 0 {
				if p.As == obj.APCALIGN {
					a := c.vregoff(&p.From)
					m = addpad(pc, a, ctxt, cursym)
				} else {
					if p.As != obj.ANOP && p.As != obj.AFUNCDATA && p.As != obj.APCDATA {
						ctxt.Diag("zero-width instruction\n%v", p)
					}
					continue
				}
			}

			// Prefixed instructions cannot be placed across a 64B boundary.
			// Mark and adjust the PC of those which do. A nop will be
			// inserted during final assembly.
			if o.ispfx {
				mark := p.Mark &^ PFX_X64B
				if pc&63 == 60 {
					p.Pc += 4
					m += 4
					mark |= PFX_X64B
				}

				// Marks may be adjusted if a too-far conditional branch is
				// fixed up above. Likewise, inserting a NOP may cause a
				// branch target to become too far away.  We need to run
				// another iteration and verify no additional changes
				// are needed.
				if mark != p.Mark {
					bflag = 1
					p.Mark = mark
				}

				// Check for 16 or 32B crossing of this prefixed insn.
				// These do no require padding, but do require increasing
				// the function alignment to prevent them from potentially
				// crossing a 64B boundary when the linker assigns the final
				// PC.
				switch p.Pc & 31 {
				case 28: // 32B crossing
					falign = 64
				case 12: // 16B crossing
					if falign < 64 {
						falign = 32
					}
				}
			}

			pc += int64(m)
		}

		c.cursym.Size = pc
	}

	c.cursym.Size = pc
	c.cursym.Func().Align = falign
	c.cursym.Grow(c.cursym.Size)

	// lay out the code, emitting code and data relocations.

	bp := c.cursym.P
	var i int32
	for p := c.cursym.Func().Text.Link; p != nil; p = p.Link {
		c.pc = p.Pc
		o = c.oplook(p)
		if int(o.size) > 4*len(out) {
			log.Fatalf("out array in span9 is too small, need at least %d for %v", o.size/4, p)
		}
		// asmout is not set up to add large amounts of padding
		if o.type_ == 0 && p.As == obj.APCALIGN {
			aln := c.vregoff(&p.From)
			v := addpad(p.Pc, aln, c.ctxt, c.cursym)
			if v > 0 {
				// Same padding instruction for all
				for i = 0; i < int32(v/4); i++ {
					c.ctxt.Arch.ByteOrder.PutUint32(bp, NOP)
					bp = bp[4:]
				}
			}
		} else {
			if p.Mark&PFX_X64B != 0 {
				c.ctxt.Arch.ByteOrder.PutUint32(bp, NOP)
				bp = bp[4:]
			}
			o.asmout(&c, p, o, &out)
			for i = 0; i < int32(o.size/4); i++ {
				c.ctxt.Arch.ByteOrder.PutUint32(bp, out[i])
				bp = bp[4:]
			}
		}
	}
}

func isint32(v int64) bool {
	return int64(int32(v)) == v
}

func isuint32(v uint64) bool {
	return uint64(uint32(v)) == v
}

func (c *ctxt9) aclassreg(reg int16) int {
	if REG_R0 <= reg && reg <= REG_R31 {
		return C_REGP + int(reg&1)
	}
	if REG_F0 <= reg && reg <= REG_F31 {
		return C_FREGP + int(reg&1)
	}
	if REG_V0 <= reg && reg <= REG_V31 {
		return C_VREG
	}
	if REG_VS0 <= reg && reg <= REG_VS63 {
		return C_VSREGP + int(reg&1)
	}
	if REG_CR0 <= reg && reg <= REG_CR7 || reg == REG_CR {
		return C_CREG
	}
	if REG_CR0LT <= reg && reg <= REG_CR7SO {
		return C_CRBIT
	}
	if REG_SPR0 <= reg && reg <= REG_SPR0+1023 {
		switch reg {
		case REG_LR:
			return C_LR

		case REG_CTR:
			return C_CTR
		}

		return C_SPR
	}
	if REG_A0 <= reg && reg <= REG_A7 {
		return C_AREG
	}
	if reg == REG_FPSCR {
		return C_FPSCR
	}
	return C_GOK
}

func (c *ctxt9) aclass(a *obj.Addr) int {
	switch a.Type {
	case obj.TYPE_NONE:
		return C_NONE

	case obj.TYPE_REG:
		return c.aclassreg(a.Reg)

	case obj.TYPE_MEM:
		if a.Index != 0 {
			if a.Name != obj.NAME_NONE || a.Offset != 0 {
				c.ctxt.Logf("Unexpected Instruction operand index %d offset %d class %d \n", a.Index, a.Offset, a.Class)

			}
			return C_XOREG
		}
		switch a.Name {
		case obj.NAME_GOTREF, obj.NAME_TOCREF:
			return C_ADDR

		case obj.NAME_EXTERN,
			obj.NAME_STATIC:
			c.instoffset = a.Offset
			if a.Sym == nil {
				break
			} else if a.Sym.Type == objabi.STLSBSS {
				// For PIC builds, use 12 byte got initial-exec TLS accesses.
				if c.ctxt.Flag_shared {
					return C_TLS_IE
				}
				// Otherwise, use 8 byte local-exec TLS accesses.
				return C_TLS_LE
			} else {
				return C_ADDR
			}

		case obj.NAME_AUTO:
			a.Reg = REGSP
			c.instoffset = int64(c.autosize) + a.Offset
			if c.instoffset >= -BIG && c.instoffset < BIG {
				return C_SOREG
			}
			return C_LOREG

		case obj.NAME_PARAM:
			a.Reg = REGSP
			c.instoffset = int64(c.autosize) + a.Offset + c.ctxt.Arch.FixedFrameSize
			if c.instoffset >= -BIG && c.instoffset < BIG {
				return C_SOREG
			}
			return C_LOREG

		case obj.NAME_NONE:
			c.instoffset = a.Offset
			if a.Offset == 0 && a.Index == 0 {
				return C_ZOREG
			} else if c.instoffset >= -BIG && c.instoffset < BIG {
				return C_SOREG
			} else {
				return C_LOREG
			}
		}

		return C_GOK

	case obj.TYPE_TEXTSIZE:
		return C_TEXTSIZE

	case obj.TYPE_FCONST:
		// The only cases where FCONST will occur are with float64 +/- 0.
		// All other float constants are generated in memory.
		f64 := a.Val.(float64)
		if f64 == 0 {
			if math.Signbit(f64) {
				return C_S16CON
			}
			return C_ZCON
		}
		log.Fatalf("Unexpected nonzero FCONST operand %v", a)

	case obj.TYPE_CONST,
		obj.TYPE_ADDR:
		switch a.Name {
		case obj.NAME_NONE:
			c.instoffset = a.Offset
			if a.Reg != 0 {
				if -BIG <= c.instoffset && c.instoffset < BIG {
					return C_SACON
				}
				if isint32(c.instoffset) {
					return C_LACON
				}
				return C_DACON
			}

		case obj.NAME_EXTERN,
			obj.NAME_STATIC:
			s := a.Sym
			if s == nil {
				return C_GOK
			}
			c.instoffset = a.Offset
			return C_LACON

		case obj.NAME_AUTO:
			a.Reg = REGSP
			c.instoffset = int64(c.autosize) + a.Offset
			if c.instoffset >= -BIG && c.instoffset < BIG {
				return C_SACON
			}
			return C_LACON

		case obj.NAME_PARAM:
			a.Reg = REGSP
			c.instoffset = int64(c.autosize) + a.Offset + c.ctxt.Arch.FixedFrameSize
			if c.instoffset >= -BIG && c.instoffset < BIG {
				return C_SACON
			}
			return C_LACON

		default:
			return C_GOK
		}

		if c.instoffset >= 0 {
			sbits := bits.Len64(uint64(c.instoffset))
			switch {
			case sbits <= 5:
				return C_ZCON + sbits
			case sbits <= 8:
				return C_U8CON
			case sbits <= 15:
				return C_U15CON
			case sbits <= 16:
				return C_U16CON
			case sbits <= 31:
				return C_U31CON
			case sbits <= 32:
				return C_U32CON
			case sbits <= 33:
				return C_S34CON
			default:
				return C_64CON
			}
		} else {
			sbits := bits.Len64(uint64(^c.instoffset))
			switch {
			case sbits <= 15:
				return C_S16CON
			case sbits <= 31:
				return C_S32CON
			case sbits <= 33:
				return C_S34CON
			default:
				return C_64CON
			}
		}

	case obj.TYPE_BRANCH:
		if a.Sym != nil && c.ctxt.Flag_dynlink && !pfxEnabled {
			return C_BRAPIC
		}
		return C_BRA
	}

	return C_GOK
}

func prasm(p *obj.Prog) {
	fmt.Printf("%v\n", p)
}

func (c *ctxt9) oplook(p *obj.Prog) *Optab {
	a1 := int(p.Optab)
	if a1 != 0 {
		return &optab[a1-1]
	}
	a1 = int(p.From.Class)
	if a1 == 0 {
		a1 = c.aclass(&p.From) + 1
		p.From.Class = int8(a1)
	}
	a1--

	argsv := [3]int{C_NONE + 1, C_NONE + 1, C_NONE + 1}
	for i, ap := range p.RestArgs {
		argsv[i] = int(ap.Addr.Class)
		if argsv[i] == 0 {
			argsv[i] = c.aclass(&ap.Addr) + 1
			ap.Addr.Class = int8(argsv[i])
		}

	}
	a3 := argsv[0] - 1
	a4 := argsv[1] - 1
	a5 := argsv[2] - 1

	a6 := int(p.To.Class)
	if a6 == 0 {
		a6 = c.aclass(&p.To) + 1
		p.To.Class = int8(a6)
	}
	a6--

	a2 := C_NONE
	if p.Reg != 0 {
		a2 = c.aclassreg(p.Reg)
	}

	// c.ctxt.Logf("oplook %v %d %d %d %d\n", p, a1, a2, a3, a4, a5, a6)
	ops := oprange[p.As&obj.AMask]
	c1 := &xcmp[a1]
	c2 := &xcmp[a2]
	c3 := &xcmp[a3]
	c4 := &xcmp[a4]
	c5 := &xcmp[a5]
	c6 := &xcmp[a6]
	for i := range ops {
		op := &ops[i]
		if c1[op.a1] && c2[op.a2] && c3[op.a3] && c4[op.a4] && c5[op.a5] && c6[op.a6] {
			p.Optab = uint16(cap(optab) - cap(ops) + i + 1)
			return op
		}
	}

	c.ctxt.Diag("illegal combination %v %v %v %v %v %v %v", p.As, DRconv(a1), DRconv(a2), DRconv(a3), DRconv(a4), DRconv(a5), DRconv(a6))
	prasm(p)
	if ops == nil {
		ops = optab
	}
	return &ops[0]
}

// Compare two operand types (ex C_REG, or C_U15CON)
// and return true if b is compatible with a.
//
// Argument comparison isn't reflexitive, so care must be taken.
// a is the argument type as found in optab, b is the argument as
// fitted by aclass.
func cmp(a int, b int) bool {
	if a == b {
		return true
	}
	switch a {

	case C_SPR:
		if b == C_LR || b == C_CTR {
			return true
		}

	case C_U1CON:
		return cmp(C_ZCON, b)
	case C_U2CON:
		return cmp(C_U1CON, b)
	case C_U3CON:
		return cmp(C_U2CON, b)
	case C_U4CON:
		return cmp(C_U3CON, b)
	case C_U5CON:
		return cmp(C_U4CON, b)
	case C_U8CON:
		return cmp(C_U5CON, b)
	case C_U15CON:
		return cmp(C_U8CON, b)
	case C_S16CON:
		return cmp(C_U15CON, b)
	case C_U16CON:
		return cmp(C_U15CON, b)
	case C_16CON:
		return cmp(C_S16CON, b) || cmp(C_U16CON, b)
	case C_U31CON:
		return cmp(C_U16CON, b)
	case C_U32CON:
		return cmp(C_U31CON, b)
	case C_S32CON:
		return cmp(C_U31CON, b) || cmp(C_S16CON, b)
	case C_32CON:
		return cmp(C_S32CON, b) || cmp(C_U32CON, b)
	case C_S34CON:
		return cmp(C_32CON, b)
	case C_64CON:
		return cmp(C_S34CON, b)

	case C_LACON:
		return cmp(C_SACON, b)

	case C_SOREG:
		return cmp(C_ZOREG, b)

	case C_LOREG:
		return cmp(C_SOREG, b)

	case C_XOREG:
		return cmp(C_REG, b) || cmp(C_ZOREG, b)

	// An even/odd register input always matches the regular register types.
	case C_REG:
		return cmp(C_REGP, b) || (b == C_ZCON && r0iszero != 0)
	case C_FREG:
		return cmp(C_FREGP, b)
	case C_VSREG:
		/* Allow any VR argument as a VSR operand. */
		return cmp(C_VSREGP, b) || cmp(C_VREG, b)

	case C_ANY:
		return true
	}

	return false
}

// Used when sorting the optab. Sorting is
// done in a way so that the best choice of
// opcode/operand combination is considered first.
func optabLess(i, j int) bool {
	p1 := &optab[i]
	p2 := &optab[j]
	n := int(p1.as) - int(p2.as)
	// same opcode
	if n != 0 {
		return n < 0
	}
	// Consider those that generate fewer
	// instructions first.
	n = int(p1.size) - int(p2.size)
	if n != 0 {
		return n < 0
	}
	// operand order should match
	// better choices first
	n = int(p1.a1) - int(p2.a1)
	if n != 0 {
		return n < 0
	}
	n = int(p1.a2) - int(p2.a2)
	if n != 0 {
		return n < 0
	}
	n = int(p1.a3) - int(p2.a3)
	if n != 0 {
		return n < 0
	}
	n = int(p1.a4) - int(p2.a4)
	if n != 0 {
		return n < 0
	}
	n = int(p1.a5) - int(p2.a5)
	if n != 0 {
		return n < 0
	}
	n = int(p1.a6) - int(p2.a6)
	if n != 0 {
		return n < 0
	}
	return false
}

// Add an entry to the opcode table for
// a new opcode b0 with the same operand combinations
// as opcode a.
func opset(a, b0 obj.As) {
	oprange[a&obj.AMask] = oprange[b0]
}

// Determine if the build configuration requires a TOC pointer.
// It is assumed this always called after buildop.
func NeedTOCpointer(ctxt *obj.Link) bool {
	return !pfxEnabled && ctxt.Flag_shared
}

// Build the opcode table
func buildop(ctxt *obj.Link) {
	// Limit PC-relative prefix instruction usage to supported and tested targets.
	pfxEnabled = buildcfg.GOPPC64 >= 10 && buildcfg.GOOS == "linux"
	cfg := fmt.Sprintf("power%d/%s/%s", buildcfg.GOPPC64, buildcfg.GOARCH, buildcfg.GOOS)
	if cfg == buildOpCfg {
		// Already initialized to correct OS/cpu; stop now.
		// This happens in the cmd/asm tests,
		// each of which re-initializes the arch.
		return
	}
	buildOpCfg = cfg

	// Configure the optab entries which may generate prefix opcodes.
	prefixOptab := make([]Optab, 0, len(prefixableOptab))
	for _, entry := range prefixableOptab {
		entry := entry
		if pfxEnabled && buildcfg.GOPPC64 >= entry.minGOPPC64 {
			// Enable prefix opcode generation and resize.
			entry.ispfx = true
			entry.size = entry.pfxsize
		}
		prefixOptab = append(prefixOptab, entry.Optab)

	}

	for i := 0; i < C_NCLASS; i++ {
		for n := 0; n < C_NCLASS; n++ {
			if cmp(n, i) {
				xcmp[i][n] = true
			}
		}
	}

	// Append the generated entries, sort, and fill out oprange.
	optab = make([]Optab, 0, len(optabBase)+len(optabGen)+len(prefixOptab))
	optab = append(optab, optabBase...)
	optab = append(optab, optabGen...)
	optab = append(optab, prefixOptab...)
	sort.Slice(optab, optabLess)

	for i := range optab {
		// Use the legacy assembler function if none provided.
		if optab[i].asmout == nil {
			optab[i].asmout = asmout
		}
	}

	for i := 0; i < len(optab); {
		r := optab[i].as
		r0 := r & obj.AMask
		start := i
		for i < len(optab) && optab[i].as == r {
			i++
		}
		oprange[r0] = optab[start:i]

		switch r {
		default:
			if !opsetGen(r) {
				ctxt.Diag("unknown op in build: %v", r)
				log.Fatalf("instruction missing from switch in asm9.go:buildop: %v", r)
			}

		case ADCBF: /* unary indexed: op (b+a); op (b) */
			opset(ADCBI, r0)

			opset(ADCBST, r0)
			opset(ADCBT, r0)
			opset(ADCBTST, r0)
			opset(ADCBZ, r0)
			opset(AICBI, r0)

		case ASTDCCC: /* indexed store: op s,(b+a); op s,(b) */
			opset(ASTWCCC, r0)
			opset(ASTHCCC, r0)
			opset(ASTBCCC, r0)

		case AREM: /* macro */
			opset(AREM, r0)

		case AREMU:
			opset(AREMU, r0)

		case AREMD:
			opset(AREMDU, r0)

		case AMULLW:
			opset(AMULLD, r0)

		case ADIVW: /* op Rb[,Ra],Rd */
			opset(AMULHW, r0)

			opset(AMULHWCC, r0)
			opset(AMULHWU, r0)
			opset(AMULHWUCC, r0)
			opset(AMULLWCC, r0)
			opset(AMULLWVCC, r0)
			opset(AMULLWV, r0)
			opset(ADIVWCC, r0)
			opset(ADIVWV, r0)
			opset(ADIVWVCC, r0)
			opset(ADIVWU, r0)
			opset(ADIVWUCC, r0)
			opset(ADIVWUV, r0)
			opset(ADIVWUVCC, r0)
			opset(AMODUD, r0)
			opset(AMODUW, r0)
			opset(AMODSD, r0)
			opset(AMODSW, r0)
			opset(AADDCC, r0)
			opset(AADDCV, r0)
			opset(AADDCVCC, r0)
			opset(AADDV, r0)
			opset(AADDVCC, r0)
			opset(AADDE, r0)
			opset(AADDECC, r0)
			opset(AADDEV, r0)
			opset(AADDEVCC, r0)
			opset(AMULHD, r0)
			opset(AMULHDCC, r0)
			opset(AMULHDU, r0)
			opset(AMULHDUCC, r0)
			opset(AMULLDCC, r0)
			opset(AMULLDVCC, r0)
			opset(AMULLDV, r0)
			opset(ADIVD, r0)
			opset(ADIVDCC, r0)
			opset(ADIVDE, r0)
			opset(ADIVDEU, r0)
			opset(ADIVDECC, r0)
			opset(ADIVDEUCC, r0)
			opset(ADIVDVCC, r0)
			opset(ADIVDV, r0)
			opset(ADIVDU, r0)
			opset(ADIVDUV, r0)
			opset(ADIVDUVCC, r0)
			opset(ADIVDUCC, r0)

		case ACRAND:
			opset(ACRANDN, r0)
			opset(ACREQV, r0)
			opset(ACRNAND, r0)
			opset(ACRNOR, r0)
			opset(ACROR, r0)
			opset(ACRORN, r0)
			opset(ACRXOR, r0)

		case APOPCNTD: /* popcntd, popcntw, popcntb, cnttzw, cnttzd */
			opset(APOPCNTW, r0)
			opset(APOPCNTB, r0)
			opset(ACNTTZW, r0)
			opset(ACNTTZWCC, r0)
			opset(ACNTTZD, r0)
			opset(ACNTTZDCC, r0)

		case ACOPY: /* copy, paste. */
			opset(APASTECC, r0)

		case AMADDHD: /* maddhd, maddhdu, maddld */
			opset(AMADDHDU, r0)
			opset(AMADDLD, r0)

		case AMOVBZ: /* lbz, stz, rlwm(r/r), lhz, lha, stz, and x variants */
			opset(AMOVH, r0)
			opset(AMOVHZ, r0)

		case AMOVBZU: /* lbz[x]u, stb[x]u, lhz[x]u, lha[x]u, sth[u]x, ld[x]u, std[u]x */
			opset(AMOVHU, r0)

			opset(AMOVHZU, r0)
			opset(AMOVWU, r0)
			opset(AMOVWZU, r0)
			opset(AMOVDU, r0)
			opset(AMOVMW, r0)

		case ALVEBX: /* lvebx, lvehx, lvewx, lvx, lvxl, lvsl, lvsr */
			opset(ALVEHX, r0)
			opset(ALVEWX, r0)
			opset(ALVX, r0)
			opset(ALVXL, r0)
			opset(ALVSL, r0)
			opset(ALVSR, r0)

		case ASTVEBX: /* stvebx, stvehx, stvewx, stvx, stvxl */
			opset(ASTVEHX, r0)
			opset(ASTVEWX, r0)
			opset(ASTVX, r0)
			opset(ASTVXL, r0)

		case AVAND: /* vand, vandc, vnand */
			opset(AVAND, r0)
			opset(AVANDC, r0)
			opset(AVNAND, r0)

		case AVMRGOW: /* vmrgew, vmrgow */
			opset(AVMRGEW, r0)

		case AVOR: /* vor, vorc, vxor, vnor, veqv */
			opset(AVOR, r0)
			opset(AVORC, r0)
			opset(AVXOR, r0)
			opset(AVNOR, r0)
			opset(AVEQV, r0)

		case AVADDUM: /* vaddubm, vadduhm, vadduwm, vaddudm, vadduqm */
			opset(AVADDUBM, r0)
			opset(AVADDUHM, r0)
			opset(AVADDUWM, r0)
			opset(AVADDUDM, r0)
			opset(AVADDUQM, r0)

		case AVADDCU: /* vaddcuq, vaddcuw */
			opset(AVADDCUQ, r0)
			opset(AVADDCUW, r0)

		case AVADDUS: /* vaddubs, vadduhs, vadduws */
			opset(AVADDUBS, r0)
			opset(AVADDUHS, r0)
			opset(AVADDUWS, r0)

		case AVADDSS: /* vaddsbs, vaddshs, vaddsws */
			opset(AVADDSBS, r0)
			opset(AVADDSHS, r0)
			opset(AVADDSWS, r0)

		case AVADDE: /* vaddeuqm, vaddecuq */
			opset(AVADDEUQM, r0)
			opset(AVADDECUQ, r0)

		case AVSUBUM: /* vsububm, vsubuhm, vsubuwm, vsubudm, vsubuqm */
			opset(AVSUBUBM, r0)
			opset(AVSUBUHM, r0)
			opset(AVSUBUWM, r0)
			opset(AVSUBUDM, r0)
			opset(AVSUBUQM, r0)

		case AVSUBCU: /* vsubcuq, vsubcuw */
			opset(AVSUBCUQ, r0)
			opset(AVSUBCUW, r0)

		case AVSUBUS: /* vsububs, vsubuhs, vsubuws */
			opset(AVSUBUBS, r0)
			opset(AVSUBUHS, r0)
			opset(AVSUBUWS, r0)

		case AVSUBSS: /* vsubsbs, vsubshs, vsubsws */
			opset(AVSUBSBS, r0)
			opset(AVSUBSHS, r0)
			opset(AVSUBSWS, r0)

		case AVSUBE: /* vsubeuqm, vsubecuq */
			opset(AVSUBEUQM, r0)
			opset(AVSUBECUQ, r0)

		case AVMULESB: /* vmulesb, vmulosb, vmuleub, vmuloub, vmulosh, vmulouh, vmulesw, vmulosw, vmuleuw, vmulouw, vmuluwm */
			opset(AVMULOSB, r0)
			opset(AVMULEUB, r0)
			opset(AVMULOUB, r0)
			opset(AVMULESH, r0)
			opset(AVMULOSH, r0)
			opset(AVMULEUH, r0)
			opset(AVMULOUH, r0)
			opset(AVMULESW, r0)
			opset(AVMULOSW, r0)
			opset(AVMULEUW, r0)
			opset(AVMULOUW, r0)
			opset(AVMULUWM, r0)
		case AVPMSUM: /* vpmsumb, vpmsumh, vpmsumw, vpmsumd */
			opset(AVPMSUMB, r0)
			opset(AVPMSUMH, r0)
			opset(AVPMSUMW, r0)
			opset(AVPMSUMD, r0)

		case AVR: /* vrlb, vrlh, vrlw, vrld */
			opset(AVRLB, r0)
			opset(AVRLH, r0)
			opset(AVRLW, r0)
			opset(AVRLD, r0)

		case AVS: /* vs[l,r], vs[l,r]o, vs[l,r]b, vs[l,r]h, vs[l,r]w, vs[l,r]d */
			opset(AVSLB, r0)
			opset(AVSLH, r0)
			opset(AVSLW, r0)
			opset(AVSL, r0)
			opset(AVSLO, r0)
			opset(AVSRB, r0)
			opset(AVSRH, r0)
			opset(AVSRW, r0)
			opset(AVSR, r0)
			opset(AVSRO, r0)
			opset(AVSLD, r0)
			opset(AVSRD, r0)

		case AVSA: /* vsrab, vsrah, vsraw, vsrad */
			opset(AVSRAB, r0)
			opset(AVSRAH, r0)
			opset(AVSRAW, r0)
			opset(AVSRAD, r0)

		case AVSOI: /* vsldoi */
			opset(AVSLDOI, r0)

		case AVCLZ: /* vclzb, vclzh, vclzw, vclzd */
			opset(AVCLZB, r0)
			opset(AVCLZH, r0)
			opset(AVCLZW, r0)
			opset(AVCLZD, r0)

		case AVPOPCNT: /* vpopcntb, vpopcnth, vpopcntw, vpopcntd */
			opset(AVPOPCNTB, r0)
			opset(AVPOPCNTH, r0)
			opset(AVPOPCNTW, r0)
			opset(AVPOPCNTD, r0)

		case AVCMPEQ: /* vcmpequb[.], vcmpequh[.], vcmpequw[.], vcmpequd[.] */
			opset(AVCMPEQUB, r0)
			opset(AVCMPEQUBCC, r0)
			opset(AVCMPEQUH, r0)
			opset(AVCMPEQUHCC, r0)
			opset(AVCMPEQUW, r0)
			opset(AVCMPEQUWCC, r0)
			opset(AVCMPEQUD, r0)
			opset(AVCMPEQUDCC, r0)

		case AVCMPGT: /* vcmpgt[u,s]b[.], vcmpgt[u,s]h[.], vcmpgt[u,s]w[.], vcmpgt[u,s]d[.] */
			opset(AVCMPGTUB, r0)
			opset(AVCMPGTUBCC, r0)
			opset(AVCMPGTUH, r0)
			opset(AVCMPGTUHCC, r0)
			opset(AVCMPGTUW, r0)
			opset(AVCMPGTUWCC, r0)
			opset(AVCMPGTUD, r0)
			opset(AVCMPGTUDCC, r0)
			opset(AVCMPGTSB, r0)
			opset(AVCMPGTSBCC, r0)
			opset(AVCMPGTSH, r0)
			opset(AVCMPGTSHCC, r0)
			opset(AVCMPGTSW, r0)
			opset(AVCMPGTSWCC, r0)
			opset(AVCMPGTSD, r0)
			opset(AVCMPGTSDCC, r0)

		case AVCMPNEZB: /* vcmpnezb[.] */
			opset(AVCMPNEZBCC, r0)
			opset(AVCMPNEB, r0)
			opset(AVCMPNEBCC, r0)
			opset(AVCMPNEH, r0)
			opset(AVCMPNEHCC, r0)
			opset(AVCMPNEW, r0)
			opset(AVCMPNEWCC, r0)

		case AVPERM: /* vperm */
			opset(AVPERMXOR, r0)
			opset(AVPERMR, r0)

		case AVBPERMQ: /* vbpermq, vbpermd */
			opset(AVBPERMD, r0)

		case AVSEL: /* vsel */
			opset(AVSEL, r0)

		case AVSPLTB: /* vspltb, vsplth, vspltw */
			opset(AVSPLTH, r0)
			opset(AVSPLTW, r0)

		case AVSPLTISB: /* vspltisb, vspltish, vspltisw */
			opset(AVSPLTISH, r0)
			opset(AVSPLTISW, r0)

		case AVCIPH: /* vcipher, vcipherlast */
			opset(AVCIPHER, r0)
			opset(AVCIPHERLAST, r0)

		case AVNCIPH: /* vncipher, vncipherlast */
			opset(AVNCIPHER, r0)
			opset(AVNCIPHERLAST, r0)

		case AVSBOX: /* vsbox */
			opset(AVSBOX, r0)

		case AVSHASIGMA: /* vshasigmaw, vshasigmad */
			opset(AVSHASIGMAW, r0)
			opset(AVSHASIGMAD, r0)

		case ALXVD2X: /* lxvd2x, lxvdsx, lxvw4x, lxvh8x, lxvb16x */
			opset(ALXVDSX, r0)
			opset(ALXVW4X, r0)
			opset(ALXVH8X, r0)
			opset(ALXVB16X, r0)

		case ALXV: /* lxv */
			opset(ALXV, r0)

		case ALXVL: /* lxvl, lxvll, lxvx */
			opset(ALXVLL, r0)
			opset(ALXVX, r0)

		case ASTXVD2X: /* stxvd2x, stxvdsx, stxvw4x, stxvh8x, stxvb16x */
			opset(ASTXVW4X, r0)
			opset(ASTXVH8X, r0)
			opset(ASTXVB16X, r0)

		case ASTXV: /* stxv */
			opset(ASTXV, r0)

		case ASTXVL: /* stxvl, stxvll, stvx */
			opset(ASTXVLL, r0)
			opset(ASTXVX, r0)

		case ALXSDX: /* lxsdx  */
			opset(ALXSDX, r0)

		case ASTXSDX: /* stxsdx */
			opset(ASTXSDX, r0)

		case ALXSIWAX: /* lxsiwax, lxsiwzx  */
			opset(ALXSIWZX, r0)

		case ASTXSIWX: /* stxsiwx */
			opset(ASTXSIWX, r0)

		case AMFVSRD: /* mfvsrd, mfvsrwz (and extended mnemonics), mfvsrld */
			opset(AMFFPRD, r0)
			opset(AMFVRD, r0)
			opset(AMFVSRWZ, r0)
			opset(AMFVSRLD, r0)

		case AMTVSRD: /* mtvsrd, mtvsrwa, mtvsrwz (and extended mnemonics), mtvsrdd, mtvsrws */
			opset(AMTFPRD, r0)
			opset(AMTVRD, r0)
			opset(AMTVSRWA, r0)
			opset(AMTVSRWZ, r0)
			opset(AMTVSRWS, r0)

		case AXXLAND:
			opset(AXXLANDC, r0)
			opset(AXXLEQV, r0)
			opset(AXXLNAND, r0)
			opset(AXXLORC, r0)
			opset(AXXLNOR, r0)
			opset(AXXLORQ, r0)
			opset(AXXLXOR, r0)
			opset(AXXLOR, r0)
			opset(AXSMAXJDP, r0)
			opset(AXSMINJDP, r0)

		case AXXSEL: /* xxsel */
			opset(AXXSEL, r0)

		case AXXMRGHW: /* xxmrghw, xxmrglw */
			opset(AXXMRGLW, r0)

		case AXXSPLTW: /* xxspltw */
			opset(AXXSPLTW, r0)

		case AXXSPLTIB: /* xxspltib */
			opset(AXXSPLTIB, r0)

		case AXXPERM: /* xxpermdi */
			opset(AXXPERM, r0)

		case AXXSLDWI: /* xxsldwi */
			opset(AXXPERMDI, r0)
			opset(AXXSLDWI, r0)

		case AXXBRQ: /* xxbrq, xxbrd, xxbrw, xxbrh */
			opset(AXXBRD, r0)
			opset(AXXBRW, r0)
			opset(AXXBRH, r0)

		case AXSCVDPSP: /* xscvdpsp, xscvspdp, xscvdpspn, xscvspdpn */
			opset(AXSCVSPDP, r0)
			opset(AXSCVDPSPN, r0)
			opset(AXSCVSPDPN, r0)

		case AXVCVDPSP: /* xvcvdpsp, xvcvspdp */
			opset(AXVCVSPDP, r0)

		case AXSCVDPSXDS: /* xscvdpsxds, xscvdpsxws, xscvdpuxds, xscvdpuxws */
			opset(AXSCVDPSXWS, r0)
			opset(AXSCVDPUXDS, r0)
			opset(AXSCVDPUXWS, r0)

		case AXSCVSXDDP: /* xscvsxddp, xscvuxddp, xscvsxdsp, xscvuxdsp */
			opset(AXSCVUXDDP, r0)
			opset(AXSCVSXDSP, r0)
			opset(AXSCVUXDSP, r0)

		case AXVCVDPSXDS: /* xvcvdpsxds, xvcvdpsxws, xvcvdpuxds, xvcvdpuxws, xvcvspsxds, xvcvspsxws, xvcvspuxds, xvcvspuxws */
			opset(AXVCVDPSXDS, r0)
			opset(AXVCVDPSXWS, r0)
			opset(AXVCVDPUXDS, r0)
			opset(AXVCVDPUXWS, r0)
			opset(AXVCVSPSXDS, r0)
			opset(AXVCVSPSXWS, r0)
			opset(AXVCVSPUXDS, r0)
			opset(AXVCVSPUXWS, r0)

		case AXVCVSXDDP: /* xvcvsxddp, xvcvsxwdp, xvcvuxddp, xvcvuxwdp, xvcvsxdsp, xvcvsxwsp, xvcvuxdsp, xvcvuxwsp */
			opset(AXVCVSXWDP, r0)
			opset(AXVCVUXDDP, r0)
			opset(AXVCVUXWDP, r0)
			opset(AXVCVSXDSP, r0)
			opset(AXVCVSXWSP, r0)
			opset(AXVCVUXDSP, r0)
			opset(AXVCVUXWSP, r0)

		case AAND: /* logical op Rb,Rs,Ra; no literal */
			opset(AANDN, r0)
			opset(AANDNCC, r0)
			opset(AEQV, r0)
			opset(AEQVCC, r0)
			opset(ANAND, r0)
			opset(ANANDCC, r0)
			opset(ANOR, r0)
			opset(ANORCC, r0)
			opset(AORCC, r0)
			opset(AORN, r0)
			opset(AORNCC, r0)
			opset(AXORCC, r0)

		case AADDME: /* op Ra, Rd */
			opset(AADDMECC, r0)

			opset(AADDMEV, r0)
			opset(AADDMEVCC, r0)
			opset(AADDZE, r0)
			opset(AADDZECC, r0)
			opset(AADDZEV, r0)
			opset(AADDZEVCC, r0)
			opset(ASUBME, r0)
			opset(ASUBMECC, r0)
			opset(ASUBMEV, r0)
			opset(ASUBMEVCC, r0)
			opset(ASUBZE, r0)
			opset(ASUBZECC, r0)
			opset(ASUBZEV, r0)
			opset(ASUBZEVCC, r0)

		case AADDC:
			opset(AADDCCC, r0)

		case ABEQ:
			opset(ABGE, r0)
			opset(ABGT, r0)
			opset(ABLE, r0)
			opset(ABLT, r0)
			opset(ABNE, r0)
			opset(ABVC, r0)
			opset(ABVS, r0)

		case ABR:
			opset(ABL, r0)

		case ABC:
			opset(ABCL, r0)

		case ABDNZ:
			opset(ABDZ, r0)

		case AEXTSB: /* op Rs, Ra */
			opset(AEXTSBCC, r0)

			opset(AEXTSH, r0)
			opset(AEXTSHCC, r0)
			opset(ACNTLZW, r0)
			opset(ACNTLZWCC, r0)
			opset(ACNTLZD, r0)
			opset(AEXTSW, r0)
			opset(AEXTSWCC, r0)
			opset(ACNTLZDCC, r0)

		case AFABS: /* fop [s,]d */
			opset(AFABSCC, r0)

			opset(AFNABS, r0)
			opset(AFNABSCC, r0)
			opset(AFNEG, r0)
			opset(AFNEGCC, r0)
			opset(AFRSP, r0)
			opset(AFRSPCC, r0)
			opset(AFCTIW, r0)
			opset(AFCTIWCC, r0)
			opset(AFCTIWZ, r0)
			opset(AFCTIWZCC, r0)
			opset(AFCTID, r0)
			opset(AFCTIDCC, r0)
			opset(AFCTIDZ, r0)
			opset(AFCTIDZCC, r0)
			opset(AFCFID, r0)
			opset(AFCFIDCC, r0)
			opset(AFCFIDU, r0)
			opset(AFCFIDUCC, r0)
			opset(AFCFIDS, r0)
			opset(AFCFIDSCC, r0)
			opset(AFRES, r0)
			opset(AFRESCC, r0)
			opset(AFRIM, r0)
			opset(AFRIMCC, r0)
			opset(AFRIP, r0)
			opset(AFRIPCC, r0)
			opset(AFRIZ, r0)
			opset(AFRIZCC, r0)
			opset(AFRIN, r0)
			opset(AFRINCC, r0)
			opset(AFRSQRTE, r0)
			opset(AFRSQRTECC, r0)
			opset(AFSQRT, r0)
			opset(AFSQRTCC, r0)
			opset(AFSQRTS, r0)
			opset(AFSQRTSCC, r0)

		case AFADD:
			opset(AFADDS, r0)
			opset(AFADDCC, r0)
			opset(AFADDSCC, r0)
			opset(AFCPSGN, r0)
			opset(AFCPSGNCC, r0)
			opset(AFDIV, r0)
			opset(AFDIVS, r0)
			opset(AFDIVCC, r0)
			opset(AFDIVSCC, r0)
			opset(AFSUB, r0)
			opset(AFSUBS, r0)
			opset(AFSUBCC, r0)
			opset(AFSUBSCC, r0)
			opset(ADADD, r0)
			opset(ADDIV, r0)
			opset(ADSUB, r0)

		case ADADDQ:
			opset(ADDIVQ, r0)
			opset(ADSUBQ, r0)

		case AFMADD:
			opset(AFMADDCC, r0)
			opset(AFMADDS, r0)
			opset(AFMADDSCC, r0)
			opset(AFMSUB, r0)
			opset(AFMSUBCC, r0)
			opset(AFMSUBS, r0)
			opset(AFMSUBSCC, r0)
			opset(AFNMADD, r0)
			opset(AFNMADDCC, r0)
			opset(AFNMADDS, r0)
			opset(AFNMADDSCC, r0)
			opset(AFNMSUB, r0)
			opset(AFNMSUBCC, r0)
			opset(AFNMSUBS, r0)
			opset(AFNMSUBSCC, r0)
			opset(AFSEL, r0)
			opset(AFSELCC, r0)

		case AFMUL:
			opset(AFMULS, r0)
			opset(AFMULCC, r0)
			opset(AFMULSCC, r0)
			opset(ADMUL, r0)

		case ADMULQ:
			opset(ADMULQ, r0)

		case AFCMPO:
			opset(AFCMPU, r0)
			opset(ADCMPU, r0)
			opset(ADCMPO, r0)

		case ADCMPOQ:
			opset(ADCMPUQ, r0)

		case AMTFSB0:
			opset(AMTFSB0CC, r0)
			opset(AMTFSB1, r0)
			opset(AMTFSB1CC, r0)

		case ANEG: /* op [Ra,] Rd */
			opset(ANEGCC, r0)

			opset(ANEGV, r0)
			opset(ANEGVCC, r0)

		case AOR: /* or/xor Rb,Rs,Ra; ori/xori $uimm,Rs,R */
			opset(AXOR, r0)

		case AORIS: /* oris/xoris $uimm,Rs,Ra */
			opset(AXORIS, r0)

		case ASLW:
			opset(ASLWCC, r0)
			opset(ASRW, r0)
			opset(ASRWCC, r0)
			opset(AROTLW, r0)

		case ASLD:
			opset(ASLDCC, r0)
			opset(ASRD, r0)
			opset(ASRDCC, r0)
			opset(AROTL, r0)

		case ASRAW: /* sraw Rb,Rs,Ra; srawi sh,Rs,Ra */
			opset(ASRAWCC, r0)

		case AEXTSWSLI:
			opset(AEXTSWSLICC, r0)

		case ASRAD: /* sraw Rb,Rs,Ra; srawi sh,Rs,Ra */
			opset(ASRADCC, r0)

		case ASUB: /* SUB Ra,Rb,Rd => subf Rd,ra,rb */
			opset(ASUB, r0)

			opset(ASUBCC, r0)
			opset(ASUBV, r0)
			opset(ASUBVCC, r0)
			opset(ASUBCCC, r0)
			opset(ASUBCV, r0)
			opset(ASUBCVCC, r0)
			opset(ASUBE, r0)
			opset(ASUBECC, r0)
			opset(ASUBEV, r0)
			opset(ASUBEVCC, r0)

		case ASYNC:
			opset(AISYNC, r0)
			opset(ALWSYNC, r0)
			opset(APTESYNC, r0)
			opset(ATLBSYNC, r0)

		case ARLWNM:
			opset(ARLWNMCC, r0)
			opset(ARLWMI, r0)
			opset(ARLWMICC, r0)

		case ARLDMI:
			opset(ARLDMICC, r0)
			opset(ARLDIMI, r0)
			opset(ARLDIMICC, r0)

		case ARLDC:
			opset(ARLDCCC, r0)

		case ARLDCL:
			opset(ARLDCR, r0)
			opset(ARLDCLCC, r0)
			opset(ARLDCRCC, r0)

		case ARLDICL:
			opset(ARLDICLCC, r0)
			opset(ARLDICR, r0)
			opset(ARLDICRCC, r0)
			opset(ARLDIC, r0)
			opset(ARLDICCC, r0)
			opset(ACLRLSLDI, r0)

		case AFMOVD:
			opset(AFMOVDCC, r0)
			opset(AFMOVDU, r0)
			opset(AFMOVS, r0)
			opset(AFMOVSU, r0)

		case ALDAR:
			opset(ALBAR, r0)
			opset(ALHAR, r0)
			opset(ALWAR, r0)

		case ASYSCALL: /* just the op; flow of control */
			opset(ARFI, r0)

			opset(ARFCI, r0)
			opset(ARFID, r0)
			opset(AHRFID, r0)

		case AMOVHBR:
			opset(AMOVWBR, r0)
			opset(AMOVDBR, r0)

		case ASLBMFEE:
			opset(ASLBMFEV, r0)

		case ATW:
			opset(ATD, r0)

		case ATLBIE:
			opset(ASLBIE, r0)
			opset(ATLBIEL, r0)

		case AEIEIO:
			opset(ASLBIA, r0)

		case ACMP:
			opset(ACMPW, r0)

		case ACMPU:
			opset(ACMPWU, r0)

		case ACMPB:
			opset(ACMPB, r0)

		case AFTDIV:
			opset(AFTDIV, r0)

		case AFTSQRT:
			opset(AFTSQRT, r0)

		case AMOVW: /* load/store/move word with sign extension; move 32-bit literals  */
			opset
"""




```