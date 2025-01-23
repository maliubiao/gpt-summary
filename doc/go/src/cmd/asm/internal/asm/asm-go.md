Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding & Context:**

The first line `// go/src/cmd/asm/internal/asm/asm.go` immediately tells us this code is part of the Go assembler. The `internal/asm` package strongly suggests it's not intended for public use but is a core component of the Go toolchain. Knowing it's the assembler significantly narrows down the possible functionalities.

**2. High-Level Purpose (Skimming the Imports and Top-Level Declarations):**

* **Imports:**  The imports give crucial clues:
    * `fmt`:  Likely for outputting information (debugging, errors).
    * `internal/abi`:  Dealing with calling conventions and ABI details.
    * `strconv`: Converting strings to numbers.
    * `strings`: String manipulation (e.g., `strings.Builder`).
    * `text/scanner`: Lexical scanning of the assembly source.
    * `cmd/asm/internal/arch`: Architecture-specific logic.
    * `cmd/asm/internal/flags`: Handling assembler flags/options.
    * `cmd/asm/internal/lex`:  Lexical analysis.
    * `cmd/internal/obj`:  Object file representation.
    * `cmd/internal/obj/ppc64`, `cmd/internal/obj/riscv`, `cmd/internal/obj/x86`:  Architecture-specific object file details.
    * `cmd/internal/sys`: System-level information (like architecture).
* **`testOut *strings.Builder`:** Suggests a testing mechanism to capture assembler output.
* **`Parser` struct and its methods:**  The core of the code revolves around a `Parser` which will process the assembly source. The methods likely correspond to different assembly constructs.

**3. Analyzing Key Functions (Focusing on Prominent and Interesting Ones):**

* **`append`:** This looks like the core function for adding assembled instructions (`obj.Prog`) to the program being built. It handles conditional execution (suffixes), label definition, and debugging output. The label handling (`p.pendingLabels`, `p.labels`) is a classic assembler task.
* **`validSymbol`, `evalInteger`, `validImmediate`:** These are helper functions to validate the types of operands used in pseudo-ops. This is essential for correct assembly.
* **`asmText`:** This clearly deals with the `TEXT` directive, which defines the start of a function. The parsing of frame size and argument size is specific to Go's calling conventions. The comment about `ABIInternal` and `NOSPLIT` is a strong indicator of its Go-specific nature.
* **`asmData`:** Handles the `DATA` directive for defining initialized data. The size specification (`/4`, `/8`) and the handling of different data types (int, float, string, address) are typical assembler functionalities. The overlap check is important for memory safety.
* **`asmGlobl`:** Implements the `GLOBL` directive for declaring global symbols. The size and flag arguments are common for controlling visibility and allocation.
* **`asmPCData`, `asmPCAlign`, `asmFuncData`:** These likely relate to metadata associated with functions, potentially for debugging, garbage collection, or stack unwinding. The names suggest "Program Counter Data" and "Function Data."
* **`asmJump`:** This is a central function for handling jump instructions. The logic to handle different operand counts and addressing modes for various architectures makes it complex. The patching mechanism (`p.toPatch`) is a standard way to resolve forward references to labels.
* **`asmInstruction`:** This is the workhorse for assembling regular instructions. The large `switch` statement based on the number of operands and the architecture highlights the need to handle diverse instruction formats. The architecture-specific checks (`arch.IsARMCMP`, `arch.IsPPC64NEG`, etc.) reinforce the idea of architecture-dependent assembly.
* **`symbolName`, `getConstantPseudo`, `getConstant`, `getImmediate`, `getRegister`:** These are utility functions for extracting and validating operand information.

**4. Inferring Overall Functionality:**

Based on the analysis of the individual functions, it's clear that `asm.go` is a core part of the Go assembler responsible for:

* **Parsing assembly source code:**  Breaking down the assembly syntax into meaningful components.
* **Validating assembly syntax:**  Ensuring that the instructions and operands are valid for the target architecture.
* **Generating machine code:**  Translating assembly instructions into their binary representations (though the actual binary encoding might be handled by other parts of the toolchain).
* **Handling pseudo-operations:**  Implementing directives like `TEXT`, `DATA`, `GLOBL`, etc., which control the assembly process and define data and functions.
* **Managing symbols and labels:**  Assigning addresses to labels and resolving references to symbols.
* **Supporting multiple architectures:** The code clearly has architecture-specific logic.
* **Facilitating Go-specific features:**  Handling Go's calling conventions, function metadata, and potentially interactions with the garbage collector.

**5. Developing Examples and Explanations:**

With the understanding of the functions' roles, it becomes easier to construct illustrative examples. For instance, knowing `asmText` handles function definitions allows creating a simple function example. Understanding `asmData` leads to examples of defining global variables. `asmJump` allows showcasing conditional and unconditional jumps.

**6. Identifying Potential User Errors:**

By examining the validation logic within the functions (e.g., in `validSymbol`, `validImmediate`), it's possible to infer common mistakes users might make, such as incorrect operand types, invalid symbol references, or missing required operands.

**7. Iterative Refinement:**

The analysis isn't necessarily linear. While looking at `asmText`, one might notice the reference to `obj.NOSPLIT` and then investigate the `cmd/internal/obj` package to understand its significance. Similarly, encountering architecture-specific functions like `arch.ARMConditionCodes` would prompt looking into the `cmd/asm/internal/arch` package.

By following these steps, combining code examination with knowledge of assembler concepts and Go's internal structure, a comprehensive understanding of the `asm.go` file can be achieved.
这段代码是 Go 语言汇编器 (`go tool asm`) 的核心组成部分，位于 `go/src/cmd/asm/internal/asm/asm.go` 文件中。它的主要功能是解析 Go 汇编源文件，并将其转换为中间表示形式，以便后续的代码生成和链接。

以下是其主要功能的详细列表和解释：

**1. 解析汇编指令和伪指令:**

* **识别各种指令和伪指令:** 代码中包含了对多种汇编指令 (如 `MOVW`, `ADD`, `JMP`) 和伪指令 (如 `TEXT`, `DATA`, `GLOBL`) 的处理逻辑。
* **解析操作数:** 能够解析各种类型的操作数，包括寄存器、立即数、内存地址、符号等。
* **处理条件码和后缀:**  对于支持条件码 (如 ARM) 和指令后缀 (如 ARM64, x86) 的架构，代码能够正确解析和应用这些修饰符。

**2. 构建中间表示 (`obj.Prog`):**

* **创建 `obj.Prog` 结构体:**  每解析一条汇编指令或伪指令，都会创建一个 `obj.Prog` 结构体来表示它。`obj.Prog` 是 Go 内部表示汇编指令的数据结构。
* **填充 `obj.Prog` 的字段:**  将解析得到的操作码、操作数等信息填充到 `obj.Prog` 结构体的相应字段中，例如 `As` (操作码), `From` (源操作数), `To` (目标操作数), `Reg` (寄存器)。
* **维护程序顺序:** 使用 `p.firstProg` 和 `p.lastProg` 链表来维护解析出的指令顺序。

**3. 处理伪指令:**

* **`TEXT`:** 处理函数定义伪指令，解析函数名、帧大小、参数大小等信息，并初始化函数符号。
* **`DATA`:** 处理数据定义伪指令，将数据写入到指定的内存地址。支持不同大小和类型的数据 (整数、浮点数、字符串、地址)。
* **`GLOBL`:** 处理全局符号定义伪指令，声明全局变量或函数，并指定其大小和标志。
* **`PCDATA` 和 `FUNCDATA`:** 处理与程序计数器和函数相关的元数据，用于调试、垃圾回收等。
* **`PCALIGN`:** 处理程序计数器对齐伪指令。

**4. 处理跳转指令和标签:**

* **解析跳转目标:** 能够解析跳转指令 (`JMP`, `B`, etc.) 的目标，可以是立即数偏移、寄存器、内存地址或标签。
* **处理标签定义:** 遇到标签定义时，将其与当前的 `obj.Prog` 关联起来，存储在 `p.labels` 中。
* **处理向前引用:** 对于在定义之前使用的标签 (向前引用)，会将其记录在 `p.toPatch` 中，并在后续解析到标签定义时进行回填。

**5. 错误处理:**

* **报告语法错误:** 当遇到无法解析的指令、操作数或伪指令时，会调用 `p.errorf` 报告错误信息。

**6. 架构特定处理:**

* **通过 `p.arch` 访问架构信息:**  代码中使用了 `p.arch` (一个 `arch.Arch` 接口的实例) 来获取当前目标架构的信息，例如寄存器名称、指令格式等。
* **调用架构特定的函数:**  对于某些需要架构特定处理的逻辑，例如条件码解析、指令后缀解析，会调用 `cmd/asm/internal/arch` 包中的函数。

**推断 Go 语言功能实现：**

这段代码是 **Go 语言汇编器** 的核心部分，负责将 `.s` 汇编源文件转换为 Go 编译器能够理解的中间表示。

**Go 代码举例说明：**

假设我们有以下简单的 Go 汇编源文件 `hello.s`:

```assembly
#include "textflag.h"

// func hello()
TEXT ·hello(SB), NOSPLIT, $0-0
    MOVW $123, R15
    RET
```

当使用 `go tool asm hello.s` 命令进行汇编时，这段 `asm.go` 中的代码会被调用来解析这个文件。

**假设的输入与输出：**

* **输入:**  `hello.s` 文件的内容（如上所示）。
* **输出:**  一个 `obj.Prog` 链表，表示解析后的汇编指令。例如，对于 `MOVW $123, R15` 这条指令，可能会生成一个 `obj.Prog` 结构体，其字段如下（简化表示）：

```go
obj.Prog{
    Ctxt: ...,
    Pos: ...,
    As:   obj.AMOVW,  // MOVW 操作码
    From: obj.Addr{Type: obj.TYPE_CONST, Offset: 123}, // 立即数 123
    To:   obj.Addr{Type: obj.TYPE_REG, Reg: 15},      // 寄存器 R15
}
```

**命令行参数的具体处理：**

虽然这段代码本身不直接处理命令行参数，但它会被 `cmd/asm/internal/asm/main.go` 调用，后者负责处理命令行参数。常见的命令行参数包括：

* `-o <outfile>`: 指定输出目标文件。
* `-D <name>=<value>`: 定义预处理器宏。
* `-I <directory>`: 指定头文件搜索路径。
* `-S`: 输出汇编列表。
* `-trimpath`: 从记录的文件路径中删除前缀。
* `-cpu <architecture>`: 指定目标 CPU 架构。这个参数会影响 `p.arch` 的值。

**使用者易犯错的点：**

* **指令拼写错误:** 汇编器对指令的拼写非常敏感，拼写错误会导致解析失败。例如，将 `MOVW` 拼写成 `MOV`。
* **操作数类型错误:**  为指令提供了错误类型的操作数。例如，某些指令只接受寄存器作为操作数，如果提供了立即数就会报错。
* **寄存器名称错误:** 使用了不存在或错误的寄存器名称。例如，在 x86 架构下使用 `R15` 而不是 `R15` (64 位寄存器)。
* **伪指令使用不当:**  `TEXT`, `DATA`, `GLOBL` 等伪指令有特定的语法和使用规则，违反这些规则会导致错误。例如，`TEXT` 指令的参数数量或格式不正确。
* **标签未定义或重复定义:** 跳转指令引用了未定义的标签，或者同一个标签被定义了多次。
* **架构特定语法错误:** 在不同的 CPU 架构下，汇编语法可能略有不同，例如寄存器命名、寻址方式等。使用了不适用于目标架构的语法。

**代码示例说明部分功能：**

```go
package main

import (
	"fmt"
	"strings"

	"cmd/asm/internal/asm"
	"cmd/asm/internal/lex"
	"cmd/internal/obj"
	"cmd/internal/sys"
)

func main() {
	source := `
TEXT ·myfunc(SB), NOSPLIT, $0-0
    MOVW $10, R1
    RET
`
	s := lex.NewStringScanner(source)
	p := asm.NewParser("", s) // 假设 "" 代表文件名，实际中需要正确的文件名
	p.Arch = &fakeArch{}     // 使用一个假的架构模拟

	err := p.Parse()
	if err != nil {
		fmt.Println("解析错误:", err)
		return
	}

	prog := p.FirstProg
	for prog != nil {
		fmt.Println(prog)
		prog = prog.Link
	}
}

// fakeArch 只是一个用于演示的假架构
type fakeArch struct {
	Family sys. গোos
}

func (f *fakeArch) CanSkipLoad(*obj.Prog) bool { return false }
func (f *fakeArch)assemble(p *asm.Parser, s *lex.Scanner, cursym *obj.LSym) {}
func (f *fakeArch) InstructionPrefix(p *obj.Prog) string { return "" }
func (f *fakeArch) RegisterPrefix() string { return "R" }
func (f *fakeArch) IsRegister(string) bool { return true }
func (f *fakeArch) IsBranch(obj.As) bool { return false }
func (f *fakeArch) IsCall(obj.As) bool { return false }
func (f *fakeArch) IsReturn(obj.As) bool { return false }
func (f *fakeArch) IsJump(obj.As) bool { return false }
func (f *fakeArch) UnaryDst map[obj.As]bool { return nil }
func (f *fakeArch) SkipFirstOperand(obj.As) bool { return false }
```

**假设输出：**

```
# ... (一些关于位置信息和上下文的输出)
TEXT    myfunc(SB),$0-0
MOVW    $0xa,R1
RET
```

这个例子演示了如何使用 `asm.Parser` 解析一段简单的汇编代码，并遍历输出解析后的 `obj.Prog` 结构体。 请注意，这只是一个简化的演示，实际的汇编过程涉及更多复杂的步骤和架构特定的处理。

### 提示词
```
这是路径为go/src/cmd/asm/internal/asm/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package asm

import (
	"fmt"
	"internal/abi"
	"strconv"
	"strings"
	"text/scanner"

	"cmd/asm/internal/arch"
	"cmd/asm/internal/flags"
	"cmd/asm/internal/lex"
	"cmd/internal/obj"
	"cmd/internal/obj/ppc64"
	"cmd/internal/obj/riscv"
	"cmd/internal/obj/x86"
	"cmd/internal/sys"
)

// TODO: configure the architecture

var testOut *strings.Builder // Gathers output when testing.

// append adds the Prog to the end of the program-thus-far.
// If doLabel is set, it also defines the labels collect for this Prog.
func (p *Parser) append(prog *obj.Prog, cond string, doLabel bool) {
	if cond != "" {
		switch p.arch.Family {
		case sys.ARM:
			if !arch.ARMConditionCodes(prog, cond) {
				p.errorf("unrecognized condition code .%q", cond)
				return
			}

		case sys.ARM64:
			if !arch.ARM64Suffix(prog, cond) {
				p.errorf("unrecognized suffix .%q", cond)
				return
			}

		case sys.AMD64, sys.I386:
			if err := x86.ParseSuffix(prog, cond); err != nil {
				p.errorf("%v", err)
				return
			}
		case sys.RISCV64:
			if err := riscv.ParseSuffix(prog, cond); err != nil {
				p.errorf("unrecognized suffix .%q", cond)
				return
			}
		default:
			p.errorf("unrecognized suffix .%q", cond)
			return
		}
	}
	if p.firstProg == nil {
		p.firstProg = prog
	} else {
		p.lastProg.Link = prog
	}
	p.lastProg = prog
	if doLabel {
		p.pc++
		for _, label := range p.pendingLabels {
			if p.labels[label] != nil {
				p.errorf("label %q multiply defined", label)
				return
			}
			p.labels[label] = prog
		}
		p.pendingLabels = p.pendingLabels[0:0]
	}
	prog.Pc = p.pc
	if *flags.Debug {
		fmt.Println(p.lineNum, prog)
	}
	if testOut != nil {
		fmt.Fprintln(testOut, prog)
	}
}

// validSymbol checks that addr represents a valid name for a pseudo-op.
func (p *Parser) validSymbol(pseudo string, addr *obj.Addr, offsetOk bool) bool {
	if addr.Sym == nil || addr.Name != obj.NAME_EXTERN && addr.Name != obj.NAME_STATIC || addr.Scale != 0 || addr.Reg != 0 {
		p.errorf("%s symbol %q must be a symbol(SB)", pseudo, symbolName(addr))
		return false
	}
	if !offsetOk && addr.Offset != 0 {
		p.errorf("%s symbol %q must not be offset from SB", pseudo, symbolName(addr))
		return false
	}
	return true
}

// evalInteger evaluates an integer constant for a pseudo-op.
func (p *Parser) evalInteger(pseudo string, operands []lex.Token) int64 {
	addr := p.address(operands)
	return p.getConstantPseudo(pseudo, &addr)
}

// validImmediate checks that addr represents an immediate constant.
func (p *Parser) validImmediate(pseudo string, addr *obj.Addr) bool {
	if addr.Type != obj.TYPE_CONST || addr.Name != 0 || addr.Reg != 0 || addr.Index != 0 {
		p.errorf("%s: expected immediate constant; found %s", pseudo, obj.Dconv(&emptyProg, addr))
		return false
	}
	return true
}

// asmText assembles a TEXT pseudo-op.
// TEXT runtime·sigtramp(SB),4,$0-0
func (p *Parser) asmText(operands [][]lex.Token) {
	if len(operands) != 2 && len(operands) != 3 {
		p.errorf("expect two or three operands for TEXT")
		return
	}

	// Labels are function scoped. Patch existing labels and
	// create a new label space for this TEXT.
	p.patch()
	p.labels = make(map[string]*obj.Prog)

	// Operand 0 is the symbol name in the form foo(SB).
	// That means symbol plus indirect on SB and no offset.
	nameAddr := p.address(operands[0])
	if !p.validSymbol("TEXT", &nameAddr, false) {
		return
	}
	name := symbolName(&nameAddr)
	next := 1

	// Next operand is the optional text flag, a literal integer.
	var flag = int64(0)
	if len(operands) == 3 {
		flag = p.evalInteger("TEXT", operands[1])
		next++
	}

	// Issue an error if we see a function defined as ABIInternal
	// without NOSPLIT. In ABIInternal, obj needs to know the function
	// signature in order to construct the morestack path, so this
	// currently isn't supported for asm functions.
	if nameAddr.Sym.ABI() == obj.ABIInternal && flag&obj.NOSPLIT == 0 {
		p.errorf("TEXT %q: ABIInternal requires NOSPLIT", name)
	}

	// Next operand is the frame and arg size.
	// Bizarre syntax: $frameSize-argSize is two words, not subtraction.
	// Both frameSize and argSize must be simple integers; only frameSize
	// can be negative.
	// The "-argSize" may be missing; if so, set it to objabi.ArgsSizeUnknown.
	// Parse left to right.
	op := operands[next]
	if len(op) < 2 || op[0].ScanToken != '$' {
		p.errorf("TEXT %s: frame size must be an immediate constant", name)
		return
	}
	op = op[1:]
	negative := false
	if op[0].ScanToken == '-' {
		negative = true
		op = op[1:]
	}
	if len(op) == 0 || op[0].ScanToken != scanner.Int {
		p.errorf("TEXT %s: frame size must be an immediate constant", name)
		return
	}
	frameSize := p.positiveAtoi(op[0].String())
	if negative {
		frameSize = -frameSize
	}
	op = op[1:]
	argSize := int64(abi.ArgsSizeUnknown)
	if len(op) > 0 {
		// There is an argument size. It must be a minus sign followed by a non-negative integer literal.
		if len(op) != 2 || op[0].ScanToken != '-' || op[1].ScanToken != scanner.Int {
			p.errorf("TEXT %s: argument size must be of form -integer", name)
			return
		}
		argSize = p.positiveAtoi(op[1].String())
	}
	p.ctxt.InitTextSym(nameAddr.Sym, int(flag), p.pos())
	prog := &obj.Prog{
		Ctxt: p.ctxt,
		As:   obj.ATEXT,
		Pos:  p.pos(),
		From: nameAddr,
		To: obj.Addr{
			Type:   obj.TYPE_TEXTSIZE,
			Offset: frameSize,
			// Argsize set below.
		},
	}
	nameAddr.Sym.Func().Text = prog
	prog.To.Val = int32(argSize)
	p.append(prog, "", true)
}

// asmData assembles a DATA pseudo-op.
// DATA masks<>+0x00(SB)/4, $0x00000000
func (p *Parser) asmData(operands [][]lex.Token) {
	if len(operands) != 2 {
		p.errorf("expect two operands for DATA")
		return
	}

	// Operand 0 has the general form foo<>+0x04(SB)/4.
	op := operands[0]
	n := len(op)
	if n < 3 || op[n-2].ScanToken != '/' || op[n-1].ScanToken != scanner.Int {
		p.errorf("expect /size for DATA argument")
		return
	}
	szop := op[n-1].String()
	sz, err := strconv.Atoi(szop)
	if err != nil {
		p.errorf("bad size for DATA argument: %q", szop)
	}
	op = op[:n-2]
	nameAddr := p.address(op)
	if !p.validSymbol("DATA", &nameAddr, true) {
		return
	}
	name := symbolName(&nameAddr)

	// Operand 1 is an immediate constant or address.
	valueAddr := p.address(operands[1])
	switch valueAddr.Type {
	case obj.TYPE_CONST, obj.TYPE_FCONST, obj.TYPE_SCONST, obj.TYPE_ADDR:
		// OK
	default:
		p.errorf("DATA value must be an immediate constant or address")
		return
	}

	// The addresses must not overlap. Easiest test: require monotonicity.
	if lastAddr, ok := p.dataAddr[name]; ok && nameAddr.Offset < lastAddr {
		p.errorf("overlapping DATA entry for %s", name)
		return
	}
	p.dataAddr[name] = nameAddr.Offset + int64(sz)

	switch valueAddr.Type {
	case obj.TYPE_CONST:
		switch sz {
		case 1, 2, 4, 8:
			nameAddr.Sym.WriteInt(p.ctxt, nameAddr.Offset, int(sz), valueAddr.Offset)
		default:
			p.errorf("bad int size for DATA argument: %d", sz)
		}
	case obj.TYPE_FCONST:
		switch sz {
		case 4:
			nameAddr.Sym.WriteFloat32(p.ctxt, nameAddr.Offset, float32(valueAddr.Val.(float64)))
		case 8:
			nameAddr.Sym.WriteFloat64(p.ctxt, nameAddr.Offset, valueAddr.Val.(float64))
		default:
			p.errorf("bad float size for DATA argument: %d", sz)
		}
	case obj.TYPE_SCONST:
		nameAddr.Sym.WriteString(p.ctxt, nameAddr.Offset, int(sz), valueAddr.Val.(string))
	case obj.TYPE_ADDR:
		if sz == p.arch.PtrSize {
			nameAddr.Sym.WriteAddr(p.ctxt, nameAddr.Offset, int(sz), valueAddr.Sym, valueAddr.Offset)
		} else {
			p.errorf("bad addr size for DATA argument: %d", sz)
		}
	}
}

// asmGlobl assembles a GLOBL pseudo-op.
// GLOBL shifts<>(SB),8,$256
// GLOBL shifts<>(SB),$256
func (p *Parser) asmGlobl(operands [][]lex.Token) {
	if len(operands) != 2 && len(operands) != 3 {
		p.errorf("expect two or three operands for GLOBL")
		return
	}

	// Operand 0 has the general form foo<>+0x04(SB).
	nameAddr := p.address(operands[0])
	if !p.validSymbol("GLOBL", &nameAddr, false) {
		return
	}
	next := 1

	// Next operand is the optional flag, a literal integer.
	var flag = int64(0)
	if len(operands) == 3 {
		flag = p.evalInteger("GLOBL", operands[1])
		next++
	}

	// Final operand is an immediate constant.
	addr := p.address(operands[next])
	if !p.validImmediate("GLOBL", &addr) {
		return
	}

	// log.Printf("GLOBL %s %d, $%d", name, flag, size)
	p.ctxt.GloblPos(nameAddr.Sym, addr.Offset, int(flag), p.pos())
}

// asmPCData assembles a PCDATA pseudo-op.
// PCDATA $2, $705
func (p *Parser) asmPCData(operands [][]lex.Token) {
	if len(operands) != 2 {
		p.errorf("expect two operands for PCDATA")
		return
	}

	// Operand 0 must be an immediate constant.
	key := p.address(operands[0])
	if !p.validImmediate("PCDATA", &key) {
		return
	}

	// Operand 1 must be an immediate constant.
	value := p.address(operands[1])
	if !p.validImmediate("PCDATA", &value) {
		return
	}

	// log.Printf("PCDATA $%d, $%d", key.Offset, value.Offset)
	prog := &obj.Prog{
		Ctxt: p.ctxt,
		As:   obj.APCDATA,
		Pos:  p.pos(),
		From: key,
		To:   value,
	}
	p.append(prog, "", true)
}

// asmPCAlign assembles a PCALIGN pseudo-op.
// PCALIGN $16
func (p *Parser) asmPCAlign(operands [][]lex.Token) {
	if len(operands) != 1 {
		p.errorf("expect one operand for PCALIGN")
		return
	}

	// Operand 0 must be an immediate constant.
	key := p.address(operands[0])
	if !p.validImmediate("PCALIGN", &key) {
		return
	}

	prog := &obj.Prog{
		Ctxt: p.ctxt,
		As:   obj.APCALIGN,
		Pos:  p.pos(),
		From: key,
	}
	p.append(prog, "", true)
}

// asmFuncData assembles a FUNCDATA pseudo-op.
// FUNCDATA $1, funcdata<>+4(SB)
func (p *Parser) asmFuncData(operands [][]lex.Token) {
	if len(operands) != 2 {
		p.errorf("expect two operands for FUNCDATA")
		return
	}

	// Operand 0 must be an immediate constant.
	valueAddr := p.address(operands[0])
	if !p.validImmediate("FUNCDATA", &valueAddr) {
		return
	}

	// Operand 1 is a symbol name in the form foo(SB).
	nameAddr := p.address(operands[1])
	if !p.validSymbol("FUNCDATA", &nameAddr, true) {
		return
	}

	prog := &obj.Prog{
		Ctxt: p.ctxt,
		As:   obj.AFUNCDATA,
		Pos:  p.pos(),
		From: valueAddr,
		To:   nameAddr,
	}
	p.append(prog, "", true)
}

// asmJump assembles a jump instruction.
// JMP	R1
// JMP	exit
// JMP	3(PC)
func (p *Parser) asmJump(op obj.As, cond string, a []obj.Addr) {
	var target *obj.Addr
	prog := &obj.Prog{
		Ctxt: p.ctxt,
		Pos:  p.pos(),
		As:   op,
	}
	targetAddr := &prog.To
	switch len(a) {
	case 0:
		if p.arch.Family == sys.Wasm {
			target = &obj.Addr{Type: obj.TYPE_NONE}
			break
		}
		p.errorf("wrong number of arguments to %s instruction", op)
		return
	case 1:
		target = &a[0]
	case 2:
		// Special 2-operand jumps.
		if p.arch.Family == sys.ARM64 && arch.IsARM64ADR(op) {
			// ADR label, R. Label is in From.
			target = &a[0]
			prog.To = a[1]
			targetAddr = &prog.From
		} else {
			target = &a[1]
			prog.From = a[0]
		}
	case 3:
		if p.arch.Family == sys.PPC64 {
			// Special 3-operand jumps.
			// a[1] is a register number expressed as a constant or register value
			target = &a[2]
			prog.From = a[0]
			if a[0].Type != obj.TYPE_CONST {
				// Legacy code may use a plain constant, accept it, and coerce
				// into a constant. E.g:
				//   BC 4,...
				// into
				//   BC $4,...
				prog.From = obj.Addr{
					Type:   obj.TYPE_CONST,
					Offset: p.getConstant(prog, op, &a[0]),
				}

			}

			// Likewise, fixup usage like:
			//   BC x,LT,...
			//   BC x,foo+2,...
			//   BC x,4
			//   BC x,$5
			// into
			//   BC x,CR0LT,...
			//   BC x,CR0EQ,...
			//   BC x,CR1LT,...
			//   BC x,CR1GT,...
			// The first and second cases demonstrate a symbol name which is
			// effectively discarded. In these cases, the offset determines
			// the CR bit.
			prog.Reg = a[1].Reg
			if a[1].Type != obj.TYPE_REG {
				// The CR bit is represented as a constant 0-31. Convert it to a Reg.
				c := p.getConstant(prog, op, &a[1])
				reg, success := ppc64.ConstantToCRbit(c)
				if !success {
					p.errorf("invalid CR bit register number %d", c)
				}
				prog.Reg = reg
			}
			break
		}
		if p.arch.Family == sys.MIPS || p.arch.Family == sys.MIPS64 || p.arch.Family == sys.RISCV64 {
			// 3-operand jumps.
			// First two must be registers
			target = &a[2]
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			break
		}
		if p.arch.Family == sys.Loong64 {
			// 3-operand jumps.
			// First two must be registers
			target = &a[2]
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			break
		}
		if p.arch.Family == sys.S390X {
			// 3-operand jumps.
			target = &a[2]
			prog.From = a[0]
			if a[1].Reg != 0 {
				// Compare two registers and jump.
				prog.Reg = p.getRegister(prog, op, &a[1])
			} else {
				// Compare register with immediate and jump.
				prog.AddRestSource(a[1])
			}
			break
		}
		if p.arch.Family == sys.ARM64 {
			// Special 3-operand jumps.
			// a[0] must be immediate constant; a[1] is a register.
			if a[0].Type != obj.TYPE_CONST {
				p.errorf("%s: expected immediate constant; found %s", op, obj.Dconv(prog, &a[0]))
				return
			}
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			target = &a[2]
			break
		}
		p.errorf("wrong number of arguments to %s instruction", op)
		return
	case 4:
		if p.arch.Family == sys.S390X || p.arch.Family == sys.PPC64 {
			// 4-operand compare-and-branch.
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			prog.AddRestSource(a[2])
			target = &a[3]
			break
		}
		p.errorf("wrong number of arguments to %s instruction", op)
		return
	default:
		p.errorf("wrong number of arguments to %s instruction", op)
		return
	}
	switch {
	case target.Type == obj.TYPE_BRANCH:
		// JMP 4(PC)
		*targetAddr = obj.Addr{
			Type:   obj.TYPE_BRANCH,
			Offset: p.pc + 1 + target.Offset, // +1 because p.pc is incremented in append, below.
		}
	case target.Type == obj.TYPE_REG:
		// JMP R1
		*targetAddr = *target
	case target.Type == obj.TYPE_MEM && (target.Name == obj.NAME_EXTERN || target.Name == obj.NAME_STATIC):
		// JMP main·morestack(SB)
		*targetAddr = *target
	case target.Type == obj.TYPE_INDIR && (target.Name == obj.NAME_EXTERN || target.Name == obj.NAME_STATIC):
		// JMP *main·morestack(SB)
		*targetAddr = *target
		targetAddr.Type = obj.TYPE_INDIR
	case target.Type == obj.TYPE_MEM && target.Reg == 0 && target.Offset == 0:
		// JMP exit
		if target.Sym == nil {
			// Parse error left name unset.
			return
		}
		targetProg := p.labels[target.Sym.Name]
		if targetProg == nil {
			p.toPatch = append(p.toPatch, Patch{targetAddr, target.Sym.Name})
		} else {
			p.branch(targetAddr, targetProg)
		}
	case target.Type == obj.TYPE_MEM && target.Name == obj.NAME_NONE:
		// JMP 4(R0)
		*targetAddr = *target
		// On the ppc64, 9a encodes BR (CTR) as BR CTR. We do the same.
		if p.arch.Family == sys.PPC64 && target.Offset == 0 {
			targetAddr.Type = obj.TYPE_REG
		}
	case target.Type == obj.TYPE_CONST:
		// JMP $4
		*targetAddr = a[0]
	case target.Type == obj.TYPE_NONE:
		// JMP
	default:
		p.errorf("cannot assemble jump %+v", target)
		return
	}

	p.append(prog, cond, true)
}

func (p *Parser) patch() {
	for _, patch := range p.toPatch {
		targetProg := p.labels[patch.label]
		if targetProg == nil {
			p.errorf("undefined label %s", patch.label)
			return
		}
		p.branch(patch.addr, targetProg)
	}
	p.toPatch = p.toPatch[:0]
}

func (p *Parser) branch(addr *obj.Addr, target *obj.Prog) {
	*addr = obj.Addr{
		Type:  obj.TYPE_BRANCH,
		Index: 0,
	}
	addr.Val = target
}

// asmInstruction assembles an instruction.
// MOVW R9, (R10)
func (p *Parser) asmInstruction(op obj.As, cond string, a []obj.Addr) {
	// fmt.Printf("%s %+v\n", op, a)
	prog := &obj.Prog{
		Ctxt: p.ctxt,
		Pos:  p.pos(),
		As:   op,
	}
	switch len(a) {
	case 0:
		// Nothing to do.
	case 1:
		if p.arch.UnaryDst[op] || op == obj.ARET || op == obj.AGETCALLERPC {
			// prog.From is no address.
			prog.To = a[0]
		} else {
			prog.From = a[0]
			// prog.To is no address.
		}
		if p.arch.Family == sys.PPC64 && arch.IsPPC64NEG(op) {
			// NEG: From and To are both a[0].
			prog.To = a[0]
			prog.From = a[0]
			break
		}
	case 2:
		if p.arch.Family == sys.ARM {
			if arch.IsARMCMP(op) {
				prog.From = a[0]
				prog.Reg = p.getRegister(prog, op, &a[1])
				break
			}
			// Strange special cases.
			if arch.IsARMFloatCmp(op) {
				prog.From = a[0]
				prog.Reg = p.getRegister(prog, op, &a[1])
				break
			}
		} else if p.arch.Family == sys.ARM64 && arch.IsARM64CMP(op) {
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			break
		} else if p.arch.Family == sys.MIPS || p.arch.Family == sys.MIPS64 {
			if arch.IsMIPSCMP(op) || arch.IsMIPSMUL(op) {
				prog.From = a[0]
				prog.Reg = p.getRegister(prog, op, &a[1])
				break
			}
		} else if p.arch.Family == sys.Loong64 {
			if arch.IsLoong64RDTIME(op) {
				// The Loong64 RDTIME family of instructions is a bit special,
				// in that both its register operands are outputs
				prog.To = a[0]
				if a[1].Type != obj.TYPE_REG {
					p.errorf("invalid addressing modes for 2nd operand to %s instruction, must be register", op)
					return
				}
				prog.RegTo2 = a[1].Reg
				break
			}
		}
		prog.From = a[0]
		prog.To = a[1]
	case 3:
		switch p.arch.Family {
		case sys.MIPS, sys.MIPS64:
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			prog.To = a[2]
		case sys.Loong64:
			switch {
			// Loong64 atomic instructions with one input and two outputs.
			case arch.IsLoong64AMO(op):
				prog.From = a[0]
				prog.To = a[1]
				prog.RegTo2 = a[2].Reg
			default:
				prog.From = a[0]
				prog.Reg = p.getRegister(prog, op, &a[1])
				prog.To = a[2]
			}
		case sys.ARM:
			// Special cases.
			if arch.IsARMSTREX(op) {
				/*
					STREX x, (y), z
						from=(y) reg=x to=z
				*/
				prog.From = a[1]
				prog.Reg = p.getRegister(prog, op, &a[0])
				prog.To = a[2]
				break
			}
			if arch.IsARMBFX(op) {
				// a[0] and a[1] must be constants, a[2] must be a register
				prog.From = a[0]
				prog.AddRestSource(a[1])
				prog.To = a[2]
				break
			}
			// Otherwise the 2nd operand (a[1]) must be a register.
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			prog.To = a[2]
		case sys.AMD64:
			prog.From = a[0]
			prog.AddRestSource(a[1])
			prog.To = a[2]
		case sys.ARM64:
			switch {
			case arch.IsARM64STLXR(op):
				// ARM64 instructions with one input and two outputs.
				prog.From = a[0]
				prog.To = a[1]
				if a[2].Type != obj.TYPE_REG {
					p.errorf("invalid addressing modes for third operand to %s instruction, must be register", op)
					return
				}
				prog.RegTo2 = a[2].Reg
			case arch.IsARM64TBL(op):
				// one of its inputs does not fit into prog.Reg.
				prog.From = a[0]
				prog.AddRestSource(a[1])
				prog.To = a[2]
			case arch.IsARM64CASP(op):
				prog.From = a[0]
				prog.To = a[1]
				// both 1st operand and 3rd operand are (Rs, Rs+1) register pair.
				// And the register pair must be contiguous.
				if (a[0].Type != obj.TYPE_REGREG) || (a[2].Type != obj.TYPE_REGREG) {
					p.errorf("invalid addressing modes for 1st or 3rd operand to %s instruction, must be register pair", op)
					return
				}
				// For ARM64 CASP-like instructions, its 2nd destination operand is register pair(Rt, Rt+1) that can
				// not fit into prog.RegTo2, so save it to the prog.RestArgs.
				prog.AddRestDest(a[2])
			default:
				prog.From = a[0]
				prog.Reg = p.getRegister(prog, op, &a[1])
				prog.To = a[2]
			}
		case sys.I386:
			prog.From = a[0]
			prog.AddRestSource(a[1])
			prog.To = a[2]
		case sys.PPC64:
			if arch.IsPPC64CMP(op) {
				// CMPW etc.; third argument is a CR register that goes into prog.Reg.
				prog.From = a[0]
				prog.Reg = p.getRegister(prog, op, &a[2])
				prog.To = a[1]
				break
			}

			prog.From = a[0]
			prog.To = a[2]

			// If the second argument is not a register argument, it must be
			// passed RestArgs/AddRestSource
			switch a[1].Type {
			case obj.TYPE_REG:
				prog.Reg = p.getRegister(prog, op, &a[1])
			default:
				prog.AddRestSource(a[1])
			}
		case sys.RISCV64:
			// RISCV64 instructions with one input and two outputs.
			if arch.IsRISCV64AMO(op) {
				prog.From = a[0]
				prog.To = a[1]
				if a[2].Type != obj.TYPE_REG {
					p.errorf("invalid addressing modes for third operand to %s instruction, must be register", op)
					return
				}
				prog.RegTo2 = a[2].Reg
				break
			}
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			prog.To = a[2]
		case sys.S390X:
			prog.From = a[0]
			if a[1].Type == obj.TYPE_REG {
				prog.Reg = p.getRegister(prog, op, &a[1])
			} else {
				prog.AddRestSource(a[1])
			}
			prog.To = a[2]
		default:
			p.errorf("TODO: implement three-operand instructions for this architecture")
			return
		}
	case 4:
		if p.arch.Family == sys.ARM {
			if arch.IsARMBFX(op) {
				// a[0] and a[1] must be constants, a[2] and a[3] must be registers
				prog.From = a[0]
				prog.AddRestSource(a[1])
				prog.Reg = p.getRegister(prog, op, &a[2])
				prog.To = a[3]
				break
			}
			if arch.IsARMMULA(op) {
				// All must be registers.
				p.getRegister(prog, op, &a[0])
				r1 := p.getRegister(prog, op, &a[1])
				r2 := p.getRegister(prog, op, &a[2])
				p.getRegister(prog, op, &a[3])
				prog.From = a[0]
				prog.To = a[3]
				prog.To.Type = obj.TYPE_REGREG2
				prog.To.Offset = int64(r2)
				prog.Reg = r1
				break
			}
		}
		if p.arch.Family == sys.AMD64 {
			prog.From = a[0]
			prog.AddRestSourceArgs([]obj.Addr{a[1], a[2]})
			prog.To = a[3]
			break
		}
		if p.arch.Family == sys.ARM64 {
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			prog.AddRestSource(a[2])
			prog.To = a[3]
			break
		}
		if p.arch.Family == sys.Loong64 {
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			prog.AddRestSource(a[2])
			prog.To = a[3]
			break
		}
		if p.arch.Family == sys.PPC64 {
			prog.From = a[0]
			prog.To = a[3]
			// If the second argument is not a register argument, it must be
			// passed RestArgs/AddRestSource
			if a[1].Type == obj.TYPE_REG {
				prog.Reg = p.getRegister(prog, op, &a[1])
				prog.AddRestSource(a[2])
			} else {
				// Don't set prog.Reg if a1 isn't a reg arg.
				prog.AddRestSourceArgs([]obj.Addr{a[1], a[2]})
			}
			break
		}
		if p.arch.Family == sys.RISCV64 {
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			prog.AddRestSource(a[2])
			prog.To = a[3]
			break
		}
		if p.arch.Family == sys.S390X {
			if a[1].Type != obj.TYPE_REG {
				p.errorf("second operand must be a register in %s instruction", op)
				return
			}
			prog.From = a[0]
			prog.Reg = p.getRegister(prog, op, &a[1])
			prog.AddRestSource(a[2])
			prog.To = a[3]
			break
		}
		p.errorf("can't handle %s instruction with 4 operands", op)
		return
	case 5:
		if p.arch.Family == sys.PPC64 {
			prog.From = a[0]
			// Second arg is always a register type on ppc64.
			prog.Reg = p.getRegister(prog, op, &a[1])
			prog.AddRestSourceArgs([]obj.Addr{a[2], a[3]})
			prog.To = a[4]
			break
		}
		if p.arch.Family == sys.AMD64 {
			prog.From = a[0]
			prog.AddRestSourceArgs([]obj.Addr{a[1], a[2], a[3]})
			prog.To = a[4]
			break
		}
		if p.arch.Family == sys.S390X {
			prog.From = a[0]
			prog.AddRestSourceArgs([]obj.Addr{a[1], a[2], a[3]})
			prog.To = a[4]
			break
		}
		p.errorf("can't handle %s instruction with 5 operands", op)
		return
	case 6:
		if p.arch.Family == sys.ARM && arch.IsARMMRC(op) {
			// Strange special case: MCR, MRC.
			prog.To.Type = obj.TYPE_CONST
			x0 := p.getConstant(prog, op, &a[0])
			x1 := p.getConstant(prog, op, &a[1])
			x2 := int64(p.getRegister(prog, op, &a[2]))
			x3 := int64(p.getRegister(prog, op, &a[3]))
			x4 := int64(p.getRegister(prog, op, &a[4]))
			x5 := p.getConstant(prog, op, &a[5])
			// Cond is handled specially for this instruction.
			offset, MRC, ok := arch.ARMMRCOffset(op, cond, x0, x1, x2, x3, x4, x5)
			if !ok {
				p.errorf("unrecognized condition code .%q", cond)
			}
			prog.To.Offset = offset
			cond = ""
			prog.As = MRC // Both instructions are coded as MRC.
			break
		}
		if p.arch.Family == sys.PPC64 {
			prog.From = a[0]
			// Second arg is always a register type on ppc64.
			prog.Reg = p.getRegister(prog, op, &a[1])
			prog.AddRestSourceArgs([]obj.Addr{a[2], a[3], a[4]})
			prog.To = a[5]
			break
		}
		fallthrough
	default:
		p.errorf("can't handle %s instruction with %d operands", op, len(a))
		return
	}

	p.append(prog, cond, true)
}

// symbolName returns the symbol name, or an error string if none is available.
func symbolName(addr *obj.Addr) string {
	if addr.Sym != nil {
		return addr.Sym.Name
	}
	return "<erroneous symbol>"
}

var emptyProg obj.Prog

// getConstantPseudo checks that addr represents a plain constant and returns its value.
func (p *Parser) getConstantPseudo(pseudo string, addr *obj.Addr) int64 {
	if addr.Type != obj.TYPE_MEM || addr.Name != 0 || addr.Reg != 0 || addr.Index != 0 {
		p.errorf("%s: expected integer constant; found %s", pseudo, obj.Dconv(&emptyProg, addr))
	}
	return addr.Offset
}

// getConstant checks that addr represents a plain constant and returns its value.
func (p *Parser) getConstant(prog *obj.Prog, op obj.As, addr *obj.Addr) int64 {
	if addr.Type != obj.TYPE_MEM || addr.Name != 0 || addr.Reg != 0 || addr.Index != 0 {
		p.errorf("%s: expected integer constant; found %s", op, obj.Dconv(prog, addr))
	}
	return addr.Offset
}

// getImmediate checks that addr represents an immediate constant and returns its value.
func (p *Parser) getImmediate(prog *obj.Prog, op obj.As, addr *obj.Addr) int64 {
	if addr.Type != obj.TYPE_CONST || addr.Name != 0 || addr.Reg != 0 || addr.Index != 0 {
		p.errorf("%s: expected immediate constant; found %s", op, obj.Dconv(prog, addr))
	}
	return addr.Offset
}

// getRegister checks that addr represents a register and returns its value.
func (p *Parser) getRegister(prog *obj.Prog, op obj.As, addr *obj.Addr) int16 {
	if addr.Type != obj.TYPE_REG || addr.Offset != 0 || addr.Name != 0 || addr.Index != 0 {
		p.errorf("%s: expected register; found %s", op, obj.Dconv(prog, addr))
	}
	return addr.Reg
}
```