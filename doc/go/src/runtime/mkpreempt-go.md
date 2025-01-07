Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Understanding the Goal:** The first step is to read the initial comment: "// mkpreempt generates the asyncPreempt functions for each architecture." This immediately tells us the core purpose of this program: to generate assembly code for different CPU architectures related to asynchronous preemption.

2. **Identifying Key Components:** Scan the code for major structures and functions. We see:
    * `package main`:  It's an executable.
    * `import` statements: Standard Go imports for flags, I/O, logging, OS interaction, and string manipulation.
    * Global variables: `regNames386`, `regNamesAMD64`, `out`, `arches`, `beLe`. These seem to hold architecture-specific data (register names) and control the generation process.
    * `main` function: The entry point of the program.
    * Helper functions: `header`, `p`, `label`. These are for output formatting.
    * Structs: `layout`, `regPos`. These likely manage the layout of data on the stack during preemption.
    * `gen...` functions:  `gen386`, `genAMD64`, `genARM`, etc. These are the core logic for generating assembly for each architecture.
    * `notImplemented`: A placeholder for architectures not yet supported.

3. **Analyzing the `main` Function:**
    * `flag.Parse()`: This indicates command-line arguments will be used.
    * Conditional execution based on `flag.NArg() > 0`:  This suggests two modes of operation: generating for specific architectures (provided as arguments) or generating for all supported architectures.
    * Loop through arguments or `arches` map:  This confirms the dual-mode operation.
    * File creation:  `os.Create(fmt.Sprintf("preempt_%s.s", arch))`. The output is assembly files named according to the architecture.
    * Calling `header(arch)` and `gen()`:  This confirms the generation flow: write a header and then generate the architecture-specific code.

4. **Examining the `arches` Map:**  This map is crucial. It links architecture names (strings) to their corresponding generation functions (`gen...`). This is the central configuration for supported architectures.

5. **Dissecting the `gen...` Functions:**  Focus on one or two as examples (e.g., `genAMD64` and `gen386`).
    * They manipulate a `layout` struct to manage stack offsets and register saving/restoring.
    * They use the `p` function to emit assembly instructions.
    * They call `·asyncPreempt2(SB)`. This is a key element – it's the function that's called to perform the actual preemption. The generated code is essentially setting up the context for this call and restoring it afterwards.
    * They handle floating-point registers separately.
    * They have architecture-specific assembly instructions.

6. **Inferring the Purpose:** Based on the file name (`mkpreempt.go`), the comment, and the generated assembly files, the program's function is clearly to generate the assembly code needed to perform asynchronous preemption in the Go runtime. Asynchronous preemption is a mechanism to interrupt a running goroutine even when it's not making function calls (where stack checks usually occur).

7. **Illustrative Go Code Example (Reasoning):** To demonstrate how this is used, we need to think about what triggers asynchronous preemption. The garbage collector is a prime candidate. When the GC needs to run, it might need to stop a running goroutine.

8. **Command-Line Argument Analysis:** The `flag` package usage points directly to command-line arguments. The behavior is clearly conditional based on whether arguments are provided.

9. **Identifying Potential Errors:**  The code itself is a generator. The potential errors are in the *generated* code if there are bugs in the `gen...` functions. However, looking at the structure, a user running this program might mistakenly provide an unsupported architecture name as a command-line argument. The `arches` map lookup and the `log.Fatalf` handle this.

10. **Structuring the Answer:** Organize the findings into the requested categories: functionality, Go feature implementation (with example), code reasoning (inputs/outputs), command-line arguments, and potential errors.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this is about signal handling. While signals *can* be involved in preemption, the `asyncPreempt` function name and the focus on saving/restoring registers point more directly to a general preemption mechanism.
* **Clarification:** The `//go:build ignore` directive is important. It means this file isn't directly compiled as part of the standard Go build. It's a *tool* to generate code.
* **Emphasis on generated code:**  Stress that this code *generates* assembly, rather than *being* the preemption mechanism itself.
* **Refining the Go example:**  Make the Go example concise and clearly illustrate the *need* for preemption.

By following these steps, combining code analysis with understanding the broader context of the Go runtime, we can arrive at a comprehensive and accurate explanation of the provided code snippet.
这段代码是Go语言运行时（runtime）的一部分，位于 `go/src/runtime/mkpreempt.go`，它的主要功能是**生成针对不同 CPU 架构的 `asyncPreempt` 汇编函数**。

**核心功能分解:**

1. **多架构支持:**  该程序的目标是为多种不同的 CPU 架构生成对应的汇编代码。它使用一个名为 `arches` 的 map 来存储架构名称和对应的代码生成函数。目前支持的架构包括：`386`, `amd64`, `arm`, `arm64`, `loong64`, `mips64x`, `mipsx`, `ppc64x`, `riscv64`, `s390x`, `wasm`。

2. **生成 `asyncPreempt` 函数:**  `asyncPreempt` 函数是 Go 运行时用来实现**异步抢占 (asynchronous preemption)** 的关键部分。异步抢占允许 Go 运行时在 Goroutine 执行过程中，即使 Goroutine 没有主动让出 CPU，也能将其暂停，以便执行其他任务（例如垃圾回收）。

3. **保存和恢复 Goroutine 上下文:**  生成的汇编代码的核心任务是保存当前 Goroutine 的 CPU 寄存器状态（包括通用寄存器、浮点寄存器、标志位等）到栈上，以便稍后能够恢复执行。不同的 CPU 架构有不同的寄存器集合和调用约定，因此需要为每种架构生成特定的保存和恢复代码。

4. **调用 `asyncPreempt2`:** 在保存完寄存器状态后，生成的汇编代码会调用 `·asyncPreempt2(SB)` 这个函数。`asyncPreempt2` 是 Go 运行时中负责处理抢占逻辑的 C 代码部分。

5. **生成汇编文件:**  该程序会为每个支持的架构生成一个名为 `preempt_<arch>.s` 的汇编文件，例如 `preempt_amd64.s`。这些文件包含了对应架构的 `asyncPreempt` 函数的汇编代码。

**它是什么 Go 语言功能的实现？**

该代码是 **Go 语言异步抢占 (Asynchronous Preemption)** 功能的底层实现的一部分。

**Go 代码举例说明:**

虽然 `mkpreempt.go` 本身是一个代码生成器，并不直接在 Go 程序中调用，但它生成的汇编代码会被 Go 运行时使用。以下是一个概念性的 Go 代码示例，展示了异步抢占的场景：

```go
package main

import (
	"fmt"
	"runtime"
	"time"
)

func longRunningTask() {
	for i := 0; ; i++ {
		// 模拟一个长时间运行的任务，没有进行任何函数调用
		if i%100000000 == 0 {
			fmt.Println("Task is still running...")
		}
	}
}

func main() {
	runtime.GOMAXPROCS(1) // 限制只使用一个 CPU 核心，更容易观察抢占

	go longRunningTask()

	time.Sleep(2 * time.Second) // 等待一段时间，让 longRunningTask 运行

	fmt.Println("Main goroutine is still alive.")

	// 在没有异步抢占的情况下，longRunningTask 可能会一直占用 CPU，
	// 导致 main goroutine 无法执行后续代码。
	// 但有了异步抢占，Go 运行时可以在适当的时候暂停 longRunningTask，
	// 让 main goroutine 获得执行机会。

	time.Sleep(5 * time.Second)
	fmt.Println("Exiting.")
}
```

**假设的输入与输出 (针对 `genAMD64` 函数):**

**假设输入：**  程序执行时，架构参数为 "amd64"。

**部分生成的 `preempt_amd64.s` 输出：**

```assembly
// Code generated by mkpreempt.go; DO NOT EDIT.

//go:build amd64

#include "go_asm.h"
#include "asm_amd64.h"
#include "textflag.h"

TEXT ·asyncPreempt(SB),NOSPLIT|NOFRAME,$0-0
	PUSHQ BP
	MOVQ SP, BP
	// Save flags before clobbering them
	PUSHFQ
	// obj doesn't understand ADD/SUB on SP, but does understand ADJSP
	ADJSP $240
	// But vet doesn't know ADJSP, so suppress vet stack checking
	NOP SP
	MOVQ AX, 0(SP)
	MOVQ CX, 8(SP)
	MOVQ DX, 16(SP)
	MOVQ BX, 24(SP)
	MOVQ SI, 40(SP)
	MOVQ DI, 48(SP)
	MOVQ R8, 56(SP)
	MOVQ R9, 64(SP)
	MOVQ R10, 72(SP)
	MOVQ R11, 80(SP)
	MOVQ R12, 88(SP)
	MOVQ R13, 96(SP)
	MOVQ R14, 104(SP)
	MOVQ R15, 112(SP)
	MOVUPS X0, 120(SP)
	MOVUPS X1, 136(SP)
	MOVUPS X2, 152(SP)
	MOVUPS X3, 168(SP)
	MOVUPS X4, 184(SP)
	MOVUPS X5, 200(SP)
	MOVUPS X6, 216(SP)
	MOVUPS X7, 232(SP)
	CALL ·asyncPreempt2(SB)
	MOVUPS 120(SP), X0
	MOVUPS 136(SP), X1
	MOVUPS 152(SP), X2
	MOVUPS 168(SP), X3
	MOVUPS 184(SP), X4
	MOVUPS 200(SP), X5
	MOVUPS 216(SP), X6
	MOVUPS 232(SP), X7
	MOVQ 0(SP), AX
	MOVQ 8(SP), CX
	MOVQ 16(SP), DX
	MOVQ 24(SP), BX
	MOVQ 40(SP), SI
	MOVQ 48(SP), DI
	MOVQ 56(SP), R8
	MOVQ 64(SP), R9
	MOVQ 72(SP), R10
	MOVQ 80(SP), R11
	MOVQ 88(SP), R12
	MOVQ 96(SP), R13
	MOVQ 104(SP), R14
	MOVQ 112(SP), R15
	ADJSP $-240
	POPFQ
	POPQ BP
	RET
```

**命令行参数的具体处理：**

该程序使用 `flag` 包来处理命令行参数。

* **没有参数:** 如果执行 `go run mkpreempt.go` 时没有提供任何参数，程序会遍历 `arches` map 中的所有架构，并为每个架构生成对应的 `preempt_<arch>.s` 文件。

* **指定架构:**  如果执行 `go run mkpreempt.go amd64 arm`，程序只会为 `amd64` 和 `arm` 这两个架构生成汇编代码，并将结果输出到标准输出 (因为 `out = os.Stdout`)。

**使用者易犯错的点：**

由于 `mkpreempt.go` 是 Go 运行时的一部分，通常开发者不会直接运行它。它主要在 Go 语言的构建过程中被调用。因此，一般使用者不会遇到直接使用上的错误。

然而，如果开发者尝试修改或扩展这个文件，可能会犯以下错误：

1. **添加新的架构但未实现 `gen<Arch>` 函数:** 如果在 `arches` map 中添加了一个新的架构名称，但没有为其实现对应的 `gen<Arch>` 函数，程序在运行时会报错。

2. **`gen<Arch>` 函数中寄存器保存和恢复逻辑错误:**  不同架构的寄存器名称、大小、调用约定都不同。在 `gen<Arch>` 函数中编写错误的汇编指令会导致生成的 `asyncPreempt` 函数无法正确保存和恢复 Goroutine 的上下文，最终导致程序崩溃或出现不可预测的行为。例如，错误地计算栈偏移、使用错误的指令保存或恢复寄存器等。

3. **忽略架构特定的细节:** 某些架构可能有特殊的寄存器或标志位需要特别处理。如果 `gen<Arch>` 函数忽略了这些细节，可能会导致抢占功能在该架构上无法正常工作。

**总结:**

`go/src/runtime/mkpreempt.go` 是一个代码生成器，它根据不同的 CPU 架构生成实现异步抢占功能的汇编代码。这个过程对于 Go 运行时的正确运行至关重要，它使得 Go 运行时能够在 Goroutine 执行过程中安全地暂停和恢复它们，从而实现并发和垃圾回收等关键功能。开发者通常不需要直接操作这个文件，但了解其功能有助于理解 Go 运行时的底层机制。

Prompt: 
```
这是路径为go/src/runtime/mkpreempt.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

// mkpreempt generates the asyncPreempt functions for each
// architecture.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// Copied from cmd/compile/internal/ssa/gen/*Ops.go

var regNames386 = []string{
	"AX",
	"CX",
	"DX",
	"BX",
	"SP",
	"BP",
	"SI",
	"DI",
	"X0",
	"X1",
	"X2",
	"X3",
	"X4",
	"X5",
	"X6",
	"X7",
}

var regNamesAMD64 = []string{
	"AX",
	"CX",
	"DX",
	"BX",
	"SP",
	"BP",
	"SI",
	"DI",
	"R8",
	"R9",
	"R10",
	"R11",
	"R12",
	"R13",
	"R14",
	"R15",
	"X0",
	"X1",
	"X2",
	"X3",
	"X4",
	"X5",
	"X6",
	"X7",
	"X8",
	"X9",
	"X10",
	"X11",
	"X12",
	"X13",
	"X14",
	"X15",
}

var out io.Writer

var arches = map[string]func(){
	"386":     gen386,
	"amd64":   genAMD64,
	"arm":     genARM,
	"arm64":   genARM64,
	"loong64": genLoong64,
	"mips64x": func() { genMIPS(true) },
	"mipsx":   func() { genMIPS(false) },
	"ppc64x":  genPPC64,
	"riscv64": genRISCV64,
	"s390x":   genS390X,
	"wasm":    genWasm,
}
var beLe = map[string]bool{"mips64x": true, "mipsx": true, "ppc64x": true}

func main() {
	flag.Parse()
	if flag.NArg() > 0 {
		out = os.Stdout
		for _, arch := range flag.Args() {
			gen, ok := arches[arch]
			if !ok {
				log.Fatalf("unknown arch %s", arch)
			}
			header(arch)
			gen()
		}
		return
	}

	for arch, gen := range arches {
		f, err := os.Create(fmt.Sprintf("preempt_%s.s", arch))
		if err != nil {
			log.Fatal(err)
		}
		out = f
		header(arch)
		gen()
		if err := f.Close(); err != nil {
			log.Fatal(err)
		}
	}
}

func header(arch string) {
	fmt.Fprintf(out, "// Code generated by mkpreempt.go; DO NOT EDIT.\n\n")
	if beLe[arch] {
		base := arch[:len(arch)-1]
		fmt.Fprintf(out, "//go:build %s || %sle\n\n", base, base)
	}
	fmt.Fprintf(out, "#include \"go_asm.h\"\n")
	if arch == "amd64" {
		fmt.Fprintf(out, "#include \"asm_amd64.h\"\n")
	}
	fmt.Fprintf(out, "#include \"textflag.h\"\n\n")
	fmt.Fprintf(out, "TEXT ·asyncPreempt(SB),NOSPLIT|NOFRAME,$0-0\n")
}

func p(f string, args ...any) {
	fmted := fmt.Sprintf(f, args...)
	fmt.Fprintf(out, "\t%s\n", strings.ReplaceAll(fmted, "\n", "\n\t"))
}

func label(l string) {
	fmt.Fprintf(out, "%s\n", l)
}

type layout struct {
	stack int
	regs  []regPos
	sp    string // stack pointer register
}

type regPos struct {
	pos int

	saveOp    string
	restoreOp string
	reg       string

	// If this register requires special save and restore, these
	// give those operations with a %d placeholder for the stack
	// offset.
	save, restore string
}

func (l *layout) add(op, reg string, size int) {
	l.regs = append(l.regs, regPos{saveOp: op, restoreOp: op, reg: reg, pos: l.stack})
	l.stack += size
}

func (l *layout) add2(sop, rop, reg string, size int) {
	l.regs = append(l.regs, regPos{saveOp: sop, restoreOp: rop, reg: reg, pos: l.stack})
	l.stack += size
}

func (l *layout) addSpecial(save, restore string, size int) {
	l.regs = append(l.regs, regPos{save: save, restore: restore, pos: l.stack})
	l.stack += size
}

func (l *layout) save() {
	for _, reg := range l.regs {
		if reg.save != "" {
			p(reg.save, reg.pos)
		} else {
			p("%s %s, %d(%s)", reg.saveOp, reg.reg, reg.pos, l.sp)
		}
	}
}

func (l *layout) restore() {
	for i := len(l.regs) - 1; i >= 0; i-- {
		reg := l.regs[i]
		if reg.restore != "" {
			p(reg.restore, reg.pos)
		} else {
			p("%s %d(%s), %s", reg.restoreOp, reg.pos, l.sp, reg.reg)
		}
	}
}

func gen386() {
	p("PUSHFL")
	// Save general purpose registers.
	var l = layout{sp: "SP"}
	for _, reg := range regNames386 {
		if reg == "SP" || strings.HasPrefix(reg, "X") {
			continue
		}
		l.add("MOVL", reg, 4)
	}

	softfloat := "GO386_softfloat"

	// Save SSE state only if supported.
	lSSE := layout{stack: l.stack, sp: "SP"}
	for i := 0; i < 8; i++ {
		lSSE.add("MOVUPS", fmt.Sprintf("X%d", i), 16)
	}

	p("ADJSP $%d", lSSE.stack)
	p("NOP SP")
	l.save()
	p("#ifndef %s", softfloat)
	lSSE.save()
	p("#endif")
	p("CALL ·asyncPreempt2(SB)")
	p("#ifndef %s", softfloat)
	lSSE.restore()
	p("#endif")
	l.restore()
	p("ADJSP $%d", -lSSE.stack)

	p("POPFL")
	p("RET")
}

func genAMD64() {
	// Assign stack offsets.
	var l = layout{sp: "SP"}
	for _, reg := range regNamesAMD64 {
		if reg == "SP" || reg == "BP" {
			continue
		}
		if !strings.HasPrefix(reg, "X") {
			l.add("MOVQ", reg, 8)
		}
	}
	lSSE := layout{stack: l.stack, sp: "SP"}
	for _, reg := range regNamesAMD64 {
		if strings.HasPrefix(reg, "X") {
			lSSE.add("MOVUPS", reg, 16)
		}
	}

	// TODO: MXCSR register?

	p("PUSHQ BP")
	p("MOVQ SP, BP")
	p("// Save flags before clobbering them")
	p("PUSHFQ")
	p("// obj doesn't understand ADD/SUB on SP, but does understand ADJSP")
	p("ADJSP $%d", lSSE.stack)
	p("// But vet doesn't know ADJSP, so suppress vet stack checking")
	p("NOP SP")

	l.save()

	lSSE.save()
	p("CALL ·asyncPreempt2(SB)")
	lSSE.restore()
	l.restore()
	p("ADJSP $%d", -lSSE.stack)
	p("POPFQ")
	p("POPQ BP")
	p("RET")
}

func genARM() {
	// Add integer registers R0-R12.
	// R13 (SP), R14 (LR), R15 (PC) are special and not saved here.
	var l = layout{sp: "R13", stack: 4} // add LR slot
	for i := 0; i <= 12; i++ {
		reg := fmt.Sprintf("R%d", i)
		if i == 10 {
			continue // R10 is g register, no need to save/restore
		}
		l.add("MOVW", reg, 4)
	}
	// Add flag register.
	l.addSpecial(
		"MOVW CPSR, R0\nMOVW R0, %d(R13)",
		"MOVW %d(R13), R0\nMOVW R0, CPSR",
		4)

	// Add floating point registers F0-F15 and flag register.
	var lfp = layout{stack: l.stack, sp: "R13"}
	lfp.addSpecial(
		"MOVW FPCR, R0\nMOVW R0, %d(R13)",
		"MOVW %d(R13), R0\nMOVW R0, FPCR",
		4)
	for i := 0; i <= 15; i++ {
		reg := fmt.Sprintf("F%d", i)
		lfp.add("MOVD", reg, 8)
	}

	p("MOVW.W R14, -%d(R13)", lfp.stack) // allocate frame, save LR
	l.save()
	p("MOVB ·goarmsoftfp(SB), R0\nCMP $0, R0\nBNE nofp") // test goarmsoftfp, and skip FP registers if goarmsoftfp!=0.
	lfp.save()
	label("nofp:")
	p("CALL ·asyncPreempt2(SB)")
	p("MOVB ·goarmsoftfp(SB), R0\nCMP $0, R0\nBNE nofp2") // test goarmsoftfp, and skip FP registers if goarmsoftfp!=0.
	lfp.restore()
	label("nofp2:")
	l.restore()

	p("MOVW %d(R13), R14", lfp.stack)     // sigctxt.pushCall pushes LR on stack, restore it
	p("MOVW.P %d(R13), R15", lfp.stack+4) // load PC, pop frame (including the space pushed by sigctxt.pushCall)
	p("UNDEF")                            // shouldn't get here
}

func genARM64() {
	// Add integer registers R0-R26
	// R27 (REGTMP), R28 (g), R29 (FP), R30 (LR), R31 (SP) are special
	// and not saved here.
	var l = layout{sp: "RSP", stack: 8} // add slot to save PC of interrupted instruction
	for i := 0; i < 26; i += 2 {
		if i == 18 {
			i--
			continue // R18 is not used, skip
		}
		reg := fmt.Sprintf("(R%d, R%d)", i, i+1)
		l.add2("STP", "LDP", reg, 16)
	}
	// Add flag registers.
	l.addSpecial(
		"MOVD NZCV, R0\nMOVD R0, %d(RSP)",
		"MOVD %d(RSP), R0\nMOVD R0, NZCV",
		8)
	l.addSpecial(
		"MOVD FPSR, R0\nMOVD R0, %d(RSP)",
		"MOVD %d(RSP), R0\nMOVD R0, FPSR",
		8)
	// TODO: FPCR? I don't think we'll change it, so no need to save.
	// Add floating point registers F0-F31.
	for i := 0; i < 31; i += 2 {
		reg := fmt.Sprintf("(F%d, F%d)", i, i+1)
		l.add2("FSTPD", "FLDPD", reg, 16)
	}
	if l.stack%16 != 0 {
		l.stack += 8 // SP needs 16-byte alignment
	}

	// allocate frame, save PC of interrupted instruction (in LR)
	p("MOVD R30, %d(RSP)", -l.stack)
	p("SUB $%d, RSP", l.stack)
	p("MOVD R29, -8(RSP)") // save frame pointer (only used on Linux)
	p("SUB $8, RSP, R29")  // set up new frame pointer
	// On iOS, save the LR again after decrementing SP. We run the
	// signal handler on the G stack (as it doesn't support sigaltstack),
	// so any writes below SP may be clobbered.
	p("#ifdef GOOS_ios")
	p("MOVD R30, (RSP)")
	p("#endif")

	l.save()
	p("CALL ·asyncPreempt2(SB)")
	l.restore()

	p("MOVD %d(RSP), R30", l.stack) // sigctxt.pushCall has pushed LR (at interrupt) on stack, restore it
	p("MOVD -8(RSP), R29")          // restore frame pointer
	p("MOVD (RSP), R27")            // load PC to REGTMP
	p("ADD $%d, RSP", l.stack+16)   // pop frame (including the space pushed by sigctxt.pushCall)
	p("JMP (R27)")
}

func genMIPS(_64bit bool) {
	mov := "MOVW"
	movf := "MOVF"
	add := "ADD"
	sub := "SUB"
	r28 := "R28"
	regsize := 4
	softfloat := "GOMIPS_softfloat"
	if _64bit {
		mov = "MOVV"
		movf = "MOVD"
		add = "ADDV"
		sub = "SUBV"
		r28 = "RSB"
		regsize = 8
		softfloat = "GOMIPS64_softfloat"
	}

	// Add integer registers R1-R22, R24-R25, R28
	// R0 (zero), R23 (REGTMP), R29 (SP), R30 (g), R31 (LR) are special,
	// and not saved here. R26 and R27 are reserved by kernel and not used.
	var l = layout{sp: "R29", stack: regsize} // add slot to save PC of interrupted instruction (in LR)
	for i := 1; i <= 25; i++ {
		if i == 23 {
			continue // R23 is REGTMP
		}
		reg := fmt.Sprintf("R%d", i)
		l.add(mov, reg, regsize)
	}
	l.add(mov, r28, regsize)
	l.addSpecial(
		mov+" HI, R1\n"+mov+" R1, %d(R29)",
		mov+" %d(R29), R1\n"+mov+" R1, HI",
		regsize)
	l.addSpecial(
		mov+" LO, R1\n"+mov+" R1, %d(R29)",
		mov+" %d(R29), R1\n"+mov+" R1, LO",
		regsize)

	// Add floating point control/status register FCR31 (FCR0-FCR30 are irrelevant)
	var lfp = layout{sp: "R29", stack: l.stack}
	lfp.addSpecial(
		mov+" FCR31, R1\n"+mov+" R1, %d(R29)",
		mov+" %d(R29), R1\n"+mov+" R1, FCR31",
		regsize)
	// Add floating point registers F0-F31.
	for i := 0; i <= 31; i++ {
		reg := fmt.Sprintf("F%d", i)
		lfp.add(movf, reg, regsize)
	}

	// allocate frame, save PC of interrupted instruction (in LR)
	p(mov+" R31, -%d(R29)", lfp.stack)
	p(sub+" $%d, R29", lfp.stack)

	l.save()
	p("#ifndef %s", softfloat)
	lfp.save()
	p("#endif")
	p("CALL ·asyncPreempt2(SB)")
	p("#ifndef %s", softfloat)
	lfp.restore()
	p("#endif")
	l.restore()

	p(mov+" %d(R29), R31", lfp.stack)     // sigctxt.pushCall has pushed LR (at interrupt) on stack, restore it
	p(mov + " (R29), R23")                // load PC to REGTMP
	p(add+" $%d, R29", lfp.stack+regsize) // pop frame (including the space pushed by sigctxt.pushCall)
	p("JMP (R23)")
}

func genLoong64() {
	mov := "MOVV"
	movf := "MOVD"
	add := "ADDV"
	sub := "SUBV"
	regsize := 8

	// Add integer registers r4-r21 r23-r29 r31
	// R0 (zero), R30 (REGTMP), R2 (tp), R3 (SP), R22 (g), R1 (LR) are special,
	var l = layout{sp: "R3", stack: regsize} // add slot to save PC of interrupted instruction (in LR)
	for i := 4; i <= 31; i++ {
		if i == 22 || i == 30 {
			continue
		}
		reg := fmt.Sprintf("R%d", i)
		l.add(mov, reg, regsize)
	}

	// Add floating point registers F0-F31.
	for i := 0; i <= 31; i++ {
		reg := fmt.Sprintf("F%d", i)
		l.add(movf, reg, regsize)
	}

	// save/restore FCC0
	l.addSpecial(
		mov+" FCC0, R4\n"+mov+" R4, %d(R3)",
		mov+" %d(R3), R4\n"+mov+" R4, FCC0",
		regsize)

	// allocate frame, save PC of interrupted instruction (in LR)
	p(mov+" R1, -%d(R3)", l.stack)
	p(sub+" $%d, R3", l.stack)

	l.save()
	p("CALL ·asyncPreempt2(SB)")
	l.restore()

	p(mov+" %d(R3), R1", l.stack)      // sigctxt.pushCall has pushed LR (at interrupt) on stack, restore it
	p(mov + " (R3), R30")              // load PC to REGTMP
	p(add+" $%d, R3", l.stack+regsize) // pop frame (including the space pushed by sigctxt.pushCall)
	p("JMP (R30)")
}

func genPPC64() {
	// Add integer registers R3-R29
	// R0 (zero), R1 (SP), R30 (g) are special and not saved here.
	// R2 (TOC pointer in PIC mode), R12 (function entry address in PIC mode) have been saved in sigctxt.pushCall.
	// R31 (REGTMP) will be saved manually.
	var l = layout{sp: "R1", stack: 32 + 8} // MinFrameSize on PPC64, plus one word for saving R31
	for i := 3; i <= 29; i++ {
		if i == 12 || i == 13 {
			// R12 has been saved in sigctxt.pushCall.
			// R13 is TLS pointer, not used by Go code. we must NOT
			// restore it, otherwise if we parked and resumed on a
			// different thread we'll mess up TLS addresses.
			continue
		}
		reg := fmt.Sprintf("R%d", i)
		l.add("MOVD", reg, 8)
	}
	l.addSpecial(
		"MOVW CR, R31\nMOVW R31, %d(R1)",
		"MOVW %d(R1), R31\nMOVFL R31, $0xff", // this is MOVW R31, CR
		8)                                    // CR is 4-byte wide, but just keep the alignment
	l.addSpecial(
		"MOVD XER, R31\nMOVD R31, %d(R1)",
		"MOVD %d(R1), R31\nMOVD R31, XER",
		8)
	// Add floating point registers F0-F31.
	for i := 0; i <= 31; i++ {
		reg := fmt.Sprintf("F%d", i)
		l.add("FMOVD", reg, 8)
	}
	// Add floating point control/status register FPSCR.
	l.addSpecial(
		"MOVFL FPSCR, F0\nFMOVD F0, %d(R1)",
		"FMOVD %d(R1), F0\nMOVFL F0, FPSCR",
		8)

	p("MOVD R31, -%d(R1)", l.stack-32) // save R31 first, we'll use R31 for saving LR
	p("MOVD LR, R31")
	p("MOVDU R31, -%d(R1)", l.stack) // allocate frame, save PC of interrupted instruction (in LR)

	l.save()
	p("CALL ·asyncPreempt2(SB)")
	l.restore()

	p("MOVD %d(R1), R31", l.stack) // sigctxt.pushCall has pushed LR, R2, R12 (at interrupt) on stack, restore them
	p("MOVD R31, LR")
	p("MOVD %d(R1), R2", l.stack+8)
	p("MOVD %d(R1), R12", l.stack+16)
	p("MOVD (R1), R31") // load PC to CTR
	p("MOVD R31, CTR")
	p("MOVD 32(R1), R31")        // restore R31
	p("ADD $%d, R1", l.stack+32) // pop frame (including the space pushed by sigctxt.pushCall)
	p("JMP (CTR)")
}

func genRISCV64() {
	// X0 (zero), X1 (LR), X2 (SP), X3 (GP), X4 (TP), X27 (g), X31 (TMP) are special.
	var l = layout{sp: "X2", stack: 8}

	// Add integer registers (X5-X26, X28-30).
	for i := 5; i < 31; i++ {
		if i == 27 {
			continue
		}
		reg := fmt.Sprintf("X%d", i)
		l.add("MOV", reg, 8)
	}

	// Add floating point registers (F0-F31).
	for i := 0; i <= 31; i++ {
		reg := fmt.Sprintf("F%d", i)
		l.add("MOVD", reg, 8)
	}

	p("MOV X1, -%d(X2)", l.stack)
	p("SUB $%d, X2", l.stack)
	l.save()
	p("CALL ·asyncPreempt2(SB)")
	l.restore()
	p("MOV %d(X2), X1", l.stack)
	p("MOV (X2), X31")
	p("ADD $%d, X2", l.stack+8)
	p("JMP (X31)")
}

func genS390X() {
	// Add integer registers R0-R12
	// R13 (g), R14 (LR), R15 (SP) are special, and not saved here.
	// Saving R10 (REGTMP) is not necessary, but it is saved anyway.
	var l = layout{sp: "R15", stack: 16} // add slot to save PC of interrupted instruction and flags
	l.addSpecial(
		"STMG R0, R12, %d(R15)",
		"LMG %d(R15), R0, R12",
		13*8)
	// Add floating point registers F0-F31.
	for i := 0; i <= 15; i++ {
		reg := fmt.Sprintf("F%d", i)
		l.add("FMOVD", reg, 8)
	}

	// allocate frame, save PC of interrupted instruction (in LR) and flags (condition code)
	p("IPM R10") // save flags upfront, as ADD will clobber flags
	p("MOVD R14, -%d(R15)", l.stack)
	p("ADD $-%d, R15", l.stack)
	p("MOVW R10, 8(R15)") // save flags

	l.save()
	p("CALL ·asyncPreempt2(SB)")
	l.restore()

	p("MOVD %d(R15), R14", l.stack)    // sigctxt.pushCall has pushed LR (at interrupt) on stack, restore it
	p("ADD $%d, R15", l.stack+8)       // pop frame (including the space pushed by sigctxt.pushCall)
	p("MOVWZ -%d(R15), R10", l.stack)  // load flags to REGTMP
	p("TMLH R10, $(3<<12)")            // restore flags
	p("MOVD -%d(R15), R10", l.stack+8) // load PC to REGTMP
	p("JMP (R10)")
}

func genWasm() {
	p("// No async preemption on wasm")
	p("UNDEF")
}

func notImplemented() {
	p("// Not implemented yet")
	p("JMP ·abort(SB)")
}

"""



```