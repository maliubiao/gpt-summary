Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding: Context is Key**

The first thing I noticed was the file path: `go/src/cmd/link/internal/arm/asm.go`. This immediately tells me this code is part of the Go linker (`cmd/link`) and is specifically dealing with the ARM architecture (`arm`). The `asm.go` suffix strongly suggests it handles assembly-level details, likely related to code generation or processing.

**2. Examining the Copyright and Imports:**

The copyright information confirms the historical roots of this code, drawing from the Inferno operating system. This hints at low-level system programming. The imports reinforce the linker context:

* `cmd/internal/objabi`: Likely deals with object file formats and ABI (Application Binary Interface) details.
* `cmd/internal/sys`:  Provides system architecture information.
* `cmd/link/internal/ld`: The core linker functionality.
* `cmd/link/internal/loader`:  Deals with loading and managing object files and symbols.
* `cmd/link/internal/sym`: Represents symbols within the linking process.
* `debug/elf`:  Indicates support for the ELF (Executable and Linkable Format) binary format, common on Linux and other Unix-like systems.
* `fmt`:  Standard formatting for output.
* `log`:  Standard logging.

**3. `gentext` Function Analysis:**

This function immediately grabbed my attention due to the assembly-like comments preceding it.

* **Assembly Snippet:** The provided assembly code is a crucial clue. It shows a sequence of ARM instructions. The comments and labels like `.align`, `local.dso_init`, `.Lmoduledata`, and the jump to `runtime.addmoduledata@plt` are strong indicators of how Go sets up dynamic linking and module initialization.
* **`ld.PrepareAddmoduledata`:** This function call suggests that `gentext` is responsible for generating code related to adding module metadata. This is a key part of Go's runtime initialization.
* **Instruction Generation (`o` function):**  The `o` function appends raw 32-bit ARM instructions. The specific opcodes (e.g., `0xe59f0004` for `ldr r0, [pc, #4]`) confirm it's directly writing machine code.
* **Relocations (`initfunc.AddRel`):** The calls to `AddRel` are essential for linking. They indicate places in the generated code where the linker needs to fill in addresses that are not known at compile time (like the address of `runtime.addmoduledata` or `local.moduledata`). The `objabi.R_CALLARM` and `objabi.R_PCREL` relocation types specify how these addresses should be calculated.

**Hypothesis from `gentext`:** This function generates the initial code that runs when a Go module is loaded. This code loads the module's metadata and registers it with the Go runtime.

**4. `braddoff` Function:**

This function's name (`br`anch `add` `off`set) and the comment about adjusting branch targets strongly suggest it manipulates branch instructions. The bitwise operations confirm it's dealing with the specific encoding of ARM branch instructions.

**5. `adddynrel` Function Analysis:**

This function is complex but crucial. The name (`add` `dyn`amic `rel`ocation) indicates it deals with relocations needed for dynamic linking.

* **Relocation Types:** The `switch r.Type()` statement handles various ARM ELF relocation types (e.g., `R_ARM_PLT32`, `R_ARM_GOT32`).
* **PLT and GOT:**  References to `PLT` (Procedure Linkage Table) and `GOT` (Global Offset Table) are classic dynamic linking concepts. The code manipulates these tables to resolve external function calls and global variable accesses at runtime.
* **`addpltsym`, `addgotsyminternal`:** These function calls suggest the creation and management of entries in the PLT and GOT.
* **`ldr.MakeSymbolUpdater`:**  This indicates modification of existing symbols during the linking process.

**Hypothesis from `adddynrel`:** This function processes relocations from ELF object files and Go's internal object files, setting up the necessary dynamic linking structures (PLT and GOT) for external symbols.

**6. `elfreloc1`, `elfsetupplt`, `machoreloc1`, `pereloc1` Functions:**

These functions with prefixes like `elf`, `macho`, and `pe` clearly handle relocation for different executable formats. `elfsetupplt` is specifically for setting up the PLT in ELF files.

**7. `trampoline` and Related Functions:**

The `trampoline` function and its related `gentramp`, `gentramppic`, and `gentrampdyn` are about generating "trampolines."  The code and comments explain that these are small code snippets inserted when a direct jump to a target is too far. This is a common technique on architectures with limited branch ranges.

**8. `archreloc` and `archrelocvariant` Functions:**

These functions seem to handle architecture-specific relocation calculations.

**9. `extreloc` Function:**

This function prepares external relocations, likely for use by an external linker.

**10. Putting it all Together:**

By analyzing the function names, comments, and the flow of operations, a coherent picture emerges:

* **`asm.go` is a core part of the ARM linker in Go.**
* **It handles the low-level details of generating ARM machine code and setting up the necessary data structures for linking.**
* **A significant portion is dedicated to supporting dynamic linking on ARM, particularly with ELF binaries.**
* **It manages the creation and manipulation of the PLT and GOT.**
* **It addresses the limitations of direct jumps by generating trampolines.**

**Generating Examples (Following the "Reasoning" Part of the Prompt):**

Based on the understanding gained above, I could then construct the Go code example showing how `gentext` contributes to module initialization. The command-line parameter explanation would focus on options that affect linking behavior (like `-buildmode`). The common mistakes section would focus on errors related to dynamic linking, like incorrect import paths or misunderstanding how PLT/GOT resolution works.

This systematic approach, starting with the overall context and gradually delving into the details of each function, allows for a comprehensive understanding of the code's purpose and functionality.
`go/src/cmd/link/internal/arm/asm.go` 是 Go 语言链接器 `cmd/link` 中专门处理 ARM 架构汇编的部分。它的主要功能是：

**1. 生成 `.text` 段中的代码片段 (gentext):**

*   **功能:**  `gentext` 函数负责生成一些启动时的代码，这些代码会被放置在最终可执行文件的 `.text` 代码段中。
*   **作用:**  这段代码主要用于在程序启动时，将当前模块的元数据（`moduledata`）添加到 Go 运行时系统中。这对于 Go 程序的模块化和运行时类型信息 (RTTI) 非常重要。
*   **代码推理:**
    *   `ld.PrepareAddmoduledata(ctxt)`: 这个函数会准备用于添加模块数据的符号和相关信息。
    *   `initfunc.AddUint32(ctxt.Arch, op)`:  向表示初始化函数的符号 `initfunc` 添加原始的 32 位 ARM 指令。
    *   生成的指令序列（`ldr r0, [pc, #4]`, `ldr r0, [r0]`, `b runtime.addmoduledata@plt`）是典型的位置无关代码 (PIC) 风格，用于加载并跳转到 `runtime.addmoduledata` 函数。
    *   `initfunc.AddRel(...)`:  添加重定位信息，告诉链接器在最终链接时如何填充指令中的地址。例如，`objabi.R_CALLARM` 表示一个 ARM 调用指令的重定位，需要指向 `runtime.addmoduledata`。`objabi.R_PCREL` 表示一个相对于程序计数器的重定位，用于加载 `local.moduledata` 的地址。
*   **Go 代码示例:**  虽然 `asm.go` 本身不直接由用户 Go 代码调用，但它生成的代码是 Go 程序启动过程不可或缺的一部分。你可以通过观察使用了多个 package 的 Go 程序在编译后的二进制文件中 `.text` 段的起始部分来大致理解其作用。
*   **假设的输入与输出:**
    *   **输入:**  链接器上下文 `ctxt`，包含目标架构信息和模块数据符号 `ctxt.Moduledata`。
    *   **输出:**  向 `initfunc` (代表初始化代码段的符号) 中添加了一段 ARM 汇编指令和相应的重定位信息。
*   **命令行参数:**  没有直接处理用户提供的命令行参数。它的行为由链接器的内部状态和目标架构决定。

**2. 处理分支指令偏移 (braddoff):**

*   **功能:** `braddoff` 函数用于调整 ARM 分支指令的目标地址。
*   **作用:** ARM 的条件分支指令和部分无条件分支指令的偏移量是 24 位的有符号数，以字（4 字节）为单位。这个函数确保在进行偏移加法时，保留高 8 位的状态，只修改低 24 位，避免超出分支指令的寻址范围。
*   **代码推理:** 函数通过位运算 `&` 和 `|` 来提取和组合指令的不同部分，实现偏移的加法。

**3. 添加动态重定位信息 (adddynrel):**

*   **功能:** `adddynrel` 函数处理将 Go 代码链接成动态库或可执行文件时需要的动态重定位。
*   **作用:**  当链接外部的共享库或进行位置无关代码链接时，需要在运行时才能确定某些符号的地址。这个函数会根据不同的重定位类型，添加相应的动态重定位条目到 ELF 文件的 `.rela.dyn` 或 `.rel.dyn` 段。
*   **代码推理:**
    *   函数根据重定位类型 `r.Type()` 进行不同的处理。
    *   对于 `objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_PLT32)`，它会处理指向外部函数的调用，如果目标符号是动态导入的，则会将其添加到 PLT (Procedure Linkage Table)。
    *   对于 `objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_GOT32)` 和 `objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_GOT_PREL)`，它处理全局变量的访问，将符号添加到 GOT (Global Offset Table)。
    *   它还处理其他类型的重定位，如绝对地址 (`R_ARM_ABS32`) 和相对地址 (`R_ARM_REL32`)。
*   **Go 代码示例:**  当你的 Go 代码调用了使用 `//go:linkname` 指令链接到外部 C 代码的函数时，`adddynrel` 就会参与处理这些外部符号的重定位。
*   **假设的输入与输出:**
    *   **输入:** 链接目标 `target`，加载器 `ldr`，架构符号表 `syms`，当前符号 `s`，重定位信息 `r`。
    *   **输出:**  可能修改当前符号 `s` 的重定位信息，例如更改重定位类型、目标符号或附加值。还可能调用其他函数来添加 PLT 或 GOT 条目。
*   **命令行参数:**  与 `-buildmode=c-shared` 或 `-buildmode=pie` 等生成动态链接产物的命令行参数相关。

**4. 生成 ELF 格式的重定位条目 (elfreloc1):**

*   **功能:** `elfreloc1` 函数将内部的 Go 重定位类型转换为 ELF 格式的重定位条目，并写入输出 buffer。
*   **作用:**  在生成 ELF 格式的可执行文件或共享库时，需要将 Go 链接器内部的重定位信息转换为标准 ELF 格式，以便操作系统加载器能够正确地进行地址调整。
*   **代码推理:**  函数根据不同的 Go 重定位类型 (`objabi.R_ADDR`, `objabi.R_PCREL`, `objabi.R_CALLARM` 等) 映射到相应的 ELF 重定位类型 (`elf.R_ARM_ABS32`, `elf.R_ARM_REL32`, `elf.R_ARM_CALL` 等)。

**5. 设置 PLT (Procedure Linkage Table) (elfsetupplt):**

*   **功能:** `elfsetupplt` 函数负责设置 ELF 文件的 PLT 表。
*   **作用:** PLT 是动态链接中的一个重要机制，用于延迟绑定外部函数的地址。当程序第一次调用一个外部函数时，PLT 会跳转到动态链接器，解析函数的地址，然后将地址写入 GOT 表，后续调用将直接从 GOT 表中获取地址。
*   **代码推理:** 函数向 `plt` 符号添加了一段标准的 PLT 序言代码。

**6. 处理 Mach-O 和 PE 格式的重定位 (machoreloc1, pereloc1):**

*   **功能:** `machoreloc1` 和 `pereloc1` 函数分别处理 Mach-O (macOS) 和 PE (Windows) 格式的重定位。
*   **作用:** 类似于 `elfreloc1`，但针对不同的可执行文件格式。

**7. 符号扩展 (signext24):**

*   **功能:** `signext24` 函数将一个 24 位的整数进行符号扩展为 32 位整数。
*   **作用:**  在处理 ARM 分支指令的偏移时，需要将 24 位的偏移量视为有符号数进行计算。

**8. 编码立即数 (immrot):**

*   **功能:** `immrot` 函数将一个 32 位立即数编码为 ARM 指令的 imm12 格式。
*   **作用:** ARM 指令的立即数编码有一定的限制，不是所有的 32 位立即数都可以直接编码。这个函数尝试将立即数旋转后放入 imm12 字段。

**9. 生成跳转 Trampoline (trampoline, gentramp, gentramppic, gentrampdyn):**

*   **功能:** 当目标地址超出直接跳转指令的范围时，这些函数会生成一个小的“跳板”代码块 (trampoline)。
*   **作用:**  Trampoline 包含无条件跳转到目标地址的指令。程序先跳转到 trampoline，再由 trampoline 跳转到最终目标，从而绕过直接跳转的距离限制。
*   `trampoline`:  主函数，判断是否需要生成 trampoline。
*   `gentramp`:  生成非 PIC (Position Independent Code) 的 trampoline。
*   `gentramppic`: 生成 PIC 的 trampoline。
*   `gentrampdyn`: 生成动态链接模式下的 trampoline (使用 GOT)。

**10. 架构相关的重定位处理 (archreloc, archrelocvariant):**

*   **功能:** `archreloc` 函数执行架构特定的重定位计算。
*   **作用:** 根据重定位类型和目标符号的值，计算出需要在指令中填入的最终值。
*   `archrelocvariant`:  处理重定位的变体情况，目前实现中直接 `log.Fatalf`，表示不支持。

**11. 外部重定位 (extreloc):**

*   **功能:** `extreloc` 函数处理外部符号的重定位。
*   **作用:** 当链接到外部对象文件时，需要为外部符号生成重定位信息。

**12. 添加 PLT 相关的重定位 (addpltreloc):**

*   **功能:** `addpltreloc` 函数向 PLT 表中添加一个条目。
*   **作用:**  为外部函数调用在 PLT 中创建相应的跳转代码。

**13. 添加 PLT 符号 (addpltsym):**

*   **功能:** `addpltsym` 函数负责将一个外部符号添加到 PLT 表中。
*   **作用:** 当链接器遇到对外部函数的调用时，会调用此函数来确保该函数在 PLT 中有对应的条目。

**14. 添加 GOT 符号 (addgotsyminternal):**

*   **功能:** `addgotsyminternal` 函数将一个符号添加到 GOT 表中。
*   **作用:**  用于访问全局变量或静态变量。

**使用者易犯错的点 (与 `cmd/link` 使用者相关):**

*   **链接外部 C 代码时的错误:**  如果使用了 `//go:linkname` 连接到外部 C 代码，但链接时没有正确指定外部库，会导致链接错误。例如，忘记在 `go build` 或 `go install` 命令中使用 `-ldflags` 指定库的路径。
    ```bash
    // mypkg/mygo.go
    package mypkg

    //go:linkname cFunc my_c_function
    func cFunc() int

    func CallC() int {
        return cFunc()
    }
    ```
    ```c
    // myclib.c
    int my_c_function() {
        return 42;
    }
    ```
    **错误示例:** `go build mypkg` (可能会报链接错误，找不到 `my_c_function`)
    **正确示例:** `gcc -c myclib.c -o myclib.o && go build -ldflags="-L. -lmyclib" mypkg` (假设 `myclib.so` 或 `myclib.a` 在当前目录)。

*   **交叉编译配置错误:** 在进行 ARM 架构的交叉编译时，如果 Go SDK 的配置不正确，或者没有安装正确的交叉编译工具链，链接过程可能会失败。

总的来说，`go/src/cmd/link/internal/arm/asm.go` 是 Go 链接器中处理 ARM 架构的底层汇编细节的关键部分。它负责生成启动代码、处理重定位、生成 PLT 和 GOT 等，是构建 ARM 平台上可执行文件的核心组件。开发者通常不需要直接与这个文件交互，但理解其功能有助于深入理解 Go 程序的链接过程和在 ARM 架构上的运行机制。

### 提示词
```
这是路径为go/src/cmd/link/internal/arm/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Inferno utils/5l/asm.c
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/5l/asm.c
//
//	Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
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

package arm

import (
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/ld"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/elf"
	"fmt"
	"log"
)

// This assembler:
//
//         .align 2
// local.dso_init:
//         ldr r0, .Lmoduledata
// .Lloadfrom:
//         ldr r0, [r0]
//         b runtime.addmoduledata@plt
// .align 2
// .Lmoduledata:
//         .word local.moduledata(GOT_PREL) + (. - (.Lloadfrom + 4))
// assembles to:
//
// 00000000 <local.dso_init>:
//    0:        e59f0004        ldr     r0, [pc, #4]    ; c <local.dso_init+0xc>
//    4:        e5900000        ldr     r0, [r0]
//    8:        eafffffe        b       0 <runtime.addmoduledata>
//                      8: R_ARM_JUMP24 runtime.addmoduledata
//    c:        00000004        .word   0x00000004
//                      c: R_ARM_GOT_PREL       local.moduledata

func gentext(ctxt *ld.Link, ldr *loader.Loader) {
	initfunc, addmoduledata := ld.PrepareAddmoduledata(ctxt)
	if initfunc == nil {
		return
	}

	o := func(op uint32) {
		initfunc.AddUint32(ctxt.Arch, op)
	}
	o(0xe59f0004)
	o(0xe08f0000)

	o(0xeafffffe)
	rel, _ := initfunc.AddRel(objabi.R_CALLARM)
	rel.SetOff(8)
	rel.SetSiz(4)
	rel.SetSym(addmoduledata)
	rel.SetAdd(0xeafffffe) // vomit

	o(0x00000000)

	rel2, _ := initfunc.AddRel(objabi.R_PCREL)
	rel2.SetOff(12)
	rel2.SetSiz(4)
	rel2.SetSym(ctxt.Moduledata)
	rel2.SetAdd(4)
}

// Preserve highest 8 bits of a, and do addition to lower 24-bit
// of a and b; used to adjust ARM branch instruction's target.
func braddoff(a int32, b int32) int32 {
	return int32((uint32(a))&0xff000000 | 0x00ffffff&uint32(a+b))
}

func adddynrel(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym, r loader.Reloc, rIdx int) bool {

	targ := r.Sym()
	var targType sym.SymKind
	if targ != 0 {
		targType = ldr.SymType(targ)
	}

	switch r.Type() {
	default:
		if r.Type() >= objabi.ElfRelocOffset {
			ldr.Errorf(s, "unexpected relocation type %d (%s)", r.Type(), sym.RelocName(target.Arch, r.Type()))
			return false
		}

	// Handle relocations found in ELF object files.
	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_PLT32):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_CALLARM)

		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			su.SetRelocSym(rIdx, syms.PLT)
			su.SetRelocAdd(rIdx, int64(braddoff(int32(r.Add()), ldr.SymPlt(targ)/4)))
		}

		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_THM_PC22): // R_ARM_THM_CALL
		ld.Exitf("R_ARM_THM_CALL, are you using -marm?")
		return false

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_GOT32): // R_ARM_GOT_BREL
		if targType != sym.SDYNIMPORT {
			addgotsyminternal(target, ldr, syms, targ)
		} else {
			ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_ARM_GLOB_DAT))
		}

		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_CONST) // write r->add during relocsym
		su.SetRelocSym(rIdx, 0)
		su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymGot(targ)))
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_GOT_PREL): // GOT(nil) + A - nil
		if targType != sym.SDYNIMPORT {
			addgotsyminternal(target, ldr, syms, targ)
		} else {
			ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_ARM_GLOB_DAT))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocSym(rIdx, syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+4+int64(ldr.SymGot(targ)))
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_GOTOFF): // R_ARM_GOTOFF32
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_GOTOFF)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_GOTPC): // R_ARM_BASE_PREL
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocSym(rIdx, syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+4)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_CALL):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_CALLARM)
		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			su.SetRelocSym(rIdx, syms.PLT)
			su.SetRelocAdd(rIdx, int64(braddoff(int32(r.Add()), ldr.SymPlt(targ)/4)))
		}
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_REL32): // R_ARM_REL32
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocAdd(rIdx, r.Add()+4)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_ABS32):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_ARM_ABS32 relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ADDR)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_PC24),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_JUMP24):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_CALLARM)
		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			su.SetRelocSym(rIdx, syms.PLT)
			su.SetRelocAdd(rIdx, int64(braddoff(int32(r.Add()), ldr.SymPlt(targ)/4)))
		}

		return true
	}

	// Handle references to ELF symbols from our own object files.
	if targType != sym.SDYNIMPORT {
		return true
	}

	// Reread the reloc to incorporate any changes in type above.
	relocs := ldr.Relocs(s)
	r = relocs.At(rIdx)

	switch r.Type() {
	case objabi.R_CALLARM:
		if target.IsExternal() {
			// External linker will do this relocation.
			return true
		}
		addpltsym(target, ldr, syms, targ)
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocSym(rIdx, syms.PLT)
		su.SetRelocAdd(rIdx, int64(braddoff(int32(r.Add()), ldr.SymPlt(targ)/4))) // TODO: don't use r.Add for instruction bytes (issue 19811)
		return true

	case objabi.R_ADDR:
		if !ldr.SymType(s).IsDATA() {
			break
		}
		if target.IsElf() {
			ld.Adddynsym(ldr, target, syms, targ)
			rel := ldr.MakeSymbolUpdater(syms.Rel)
			rel.AddAddrPlus(target.Arch, s, int64(r.Off()))
			rel.AddUint32(target.Arch, elf.R_INFO32(uint32(ldr.SymDynid(targ)), uint32(elf.R_ARM_GLOB_DAT))) // we need a nil + A dynamic reloc
			su := ldr.MakeSymbolUpdater(s)
			su.SetRelocType(rIdx, objabi.R_CONST) // write r->add during relocsym
			su.SetRelocSym(rIdx, 0)
			return true
		}

	case objabi.R_GOTPCREL:
		if target.IsExternal() {
			// External linker will do this relocation.
			return true
		}
		if targType != sym.SDYNIMPORT {
			ldr.Errorf(s, "R_GOTPCREL target is not SDYNIMPORT symbol: %v", ldr.SymName(targ))
		}
		ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_ARM_GLOB_DAT))
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocSym(rIdx, syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymGot(targ)))
		return true
	}

	return false
}

func elfreloc1(ctxt *ld.Link, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, ri int, sectoff int64) bool {
	out.Write32(uint32(sectoff))

	elfsym := ld.ElfSymForReloc(ctxt, r.Xsym)
	siz := r.Size
	switch r.Type {
	default:
		return false
	case objabi.R_ADDR, objabi.R_DWARFSECREF:
		if siz == 4 {
			out.Write32(uint32(elf.R_ARM_ABS32) | uint32(elfsym)<<8)
		} else {
			return false
		}
	case objabi.R_PCREL:
		if siz == 4 {
			out.Write32(uint32(elf.R_ARM_REL32) | uint32(elfsym)<<8)
		} else {
			return false
		}
	case objabi.R_CALLARM:
		if siz == 4 {
			relocs := ldr.Relocs(s)
			r := relocs.At(ri)
			if r.Add()&0xff000000 == 0xeb000000 { // BL // TODO: using r.Add here is bad (issue 19811)
				out.Write32(uint32(elf.R_ARM_CALL) | uint32(elfsym)<<8)
			} else {
				out.Write32(uint32(elf.R_ARM_JUMP24) | uint32(elfsym)<<8)
			}
		} else {
			return false
		}
	case objabi.R_TLS_LE:
		out.Write32(uint32(elf.R_ARM_TLS_LE32) | uint32(elfsym)<<8)
	case objabi.R_TLS_IE:
		out.Write32(uint32(elf.R_ARM_TLS_IE32) | uint32(elfsym)<<8)
	case objabi.R_GOTPCREL:
		if siz == 4 {
			out.Write32(uint32(elf.R_ARM_GOT_PREL) | uint32(elfsym)<<8)
		} else {
			return false
		}
	}

	return true
}

func elfsetupplt(ctxt *ld.Link, ldr *loader.Loader, plt, got *loader.SymbolBuilder, dynamic loader.Sym) {
	if plt.Size() == 0 {
		// str lr, [sp, #-4]!
		plt.AddUint32(ctxt.Arch, 0xe52de004)

		// ldr lr, [pc, #4]
		plt.AddUint32(ctxt.Arch, 0xe59fe004)

		// add lr, pc, lr
		plt.AddUint32(ctxt.Arch, 0xe08fe00e)

		// ldr pc, [lr, #8]!
		plt.AddUint32(ctxt.Arch, 0xe5bef008)

		// .word &GLOBAL_OFFSET_TABLE[0] - .
		plt.AddPCRelPlus(ctxt.Arch, got.Sym(), 4)

		// the first .plt entry requires 3 .plt.got entries
		got.AddUint32(ctxt.Arch, 0)

		got.AddUint32(ctxt.Arch, 0)
		got.AddUint32(ctxt.Arch, 0)
	}
}

func machoreloc1(*sys.Arch, *ld.OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool {
	return false
}

func pereloc1(arch *sys.Arch, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, sectoff int64) bool {
	rs := r.Xsym
	rt := r.Type

	if ldr.SymDynid(rs) < 0 {
		ldr.Errorf(s, "reloc %d (%s) to non-coff symbol %s type=%d (%s)", rt, sym.RelocName(arch, rt), ldr.SymName(rs), ldr.SymType(rs), ldr.SymType(rs))
		return false
	}

	out.Write32(uint32(sectoff))
	out.Write32(uint32(ldr.SymDynid(rs)))

	var v uint32
	switch rt {
	default:
		// unsupported relocation type
		return false

	case objabi.R_DWARFSECREF:
		v = ld.IMAGE_REL_ARM_SECREL

	case objabi.R_ADDR:
		v = ld.IMAGE_REL_ARM_ADDR32

	case objabi.R_PEIMAGEOFF:
		v = ld.IMAGE_REL_ARM_ADDR32NB
	}

	out.Write16(uint16(v))

	return true
}

// sign extend a 24-bit integer.
func signext24(x int64) int32 {
	return (int32(x) << 8) >> 8
}

// encode an immediate in ARM's imm12 format. copied from ../../../internal/obj/arm/asm5.go
func immrot(v uint32) uint32 {
	for i := 0; i < 16; i++ {
		if v&^0xff == 0 {
			return uint32(i<<8) | v | 1<<25
		}
		v = v<<2 | v>>30
	}
	return 0
}

// Convert the direct jump relocation r to refer to a trampoline if the target is too far.
func trampoline(ctxt *ld.Link, ldr *loader.Loader, ri int, rs, s loader.Sym) {
	relocs := ldr.Relocs(s)
	r := relocs.At(ri)
	switch r.Type() {
	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_CALL),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_PC24),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_ARM_JUMP24):
		// Host object relocations that will be turned into a PLT call.
		// The PLT may be too far. Insert a trampoline for them.
		fallthrough
	case objabi.R_CALLARM:
		var t int64
		// ldr.SymValue(rs) == 0 indicates a cross-package jump to a function that is not yet
		// laid out. Conservatively use a trampoline. This should be rare, as we lay out packages
		// in dependency order.
		if ldr.SymValue(rs) != 0 {
			// Workaround for issue #58425: it appears that the
			// external linker doesn't always take into account the
			// relocation addend when doing reachability checks. This
			// means that if you have a call from function XYZ at
			// offset 8 to runtime.duffzero with addend 800 (for
			// example), where the distance between the start of XYZ
			// and the start of runtime.duffzero is just over the
			// limit (by 100 bytes, say), you can get "relocation
			// doesn't fit" errors from the external linker. To deal
			// with this, ignore the addend when performing the
			// distance calculation (this assumes that we're only
			// handling backward jumps; ideally we might want to check
			// both with and without the addend).
			if ctxt.IsExternal() {
				t = (ldr.SymValue(rs) - (ldr.SymValue(s) + int64(r.Off()))) / 4
			} else {
				// r.Add is the instruction
				// low 24-bit encodes the target address
				t = (ldr.SymValue(rs) + int64(signext24(r.Add()&0xffffff)*4) - (ldr.SymValue(s) + int64(r.Off()))) / 4
			}
		}
		if t > 0x7fffff || t <= -0x800000 || ldr.SymValue(rs) == 0 || (*ld.FlagDebugTramp > 1 && ldr.SymPkg(s) != ldr.SymPkg(rs)) {
			// direct call too far, need to insert trampoline.
			// look up existing trampolines first. if we found one within the range
			// of direct call, we can reuse it. otherwise create a new one.
			offset := (signext24(r.Add()&0xffffff) + 2) * 4
			var tramp loader.Sym
			for i := 0; ; i++ {
				oName := ldr.SymName(rs)
				name := oName + fmt.Sprintf("%+d-tramp%d", offset, i)
				tramp = ldr.LookupOrCreateSym(name, int(ldr.SymVersion(rs)))
				ldr.SetAttrReachable(tramp, true)
				if ldr.SymType(tramp) == sym.SDYNIMPORT {
					// don't reuse trampoline defined in other module
					continue
				}
				if oName == "runtime.deferreturn" {
					ldr.SetIsDeferReturnTramp(tramp, true)
				}
				if ldr.SymValue(tramp) == 0 {
					// either the trampoline does not exist -- we need to create one,
					// or found one the address which is not assigned -- this will be
					// laid down immediately after the current function. use this one.
					break
				}

				t = (ldr.SymValue(tramp) - 8 - (ldr.SymValue(s) + int64(r.Off()))) / 4
				if t >= -0x800000 && t < 0x7fffff {
					// found an existing trampoline that is not too far
					// we can just use it
					break
				}
			}
			if ldr.SymType(tramp) == 0 {
				// trampoline does not exist, create one
				trampb := ldr.MakeSymbolUpdater(tramp)
				ctxt.AddTramp(trampb, ldr.SymType(s))
				if ctxt.DynlinkingGo() || ldr.SymType(rs) == sym.SDYNIMPORT {
					if immrot(uint32(offset)) == 0 {
						ctxt.Errorf(s, "odd offset in dynlink direct call: %v+%d", ldr.SymName(rs), offset)
					}
					gentrampdyn(ctxt.Arch, trampb, rs, int64(offset))
				} else if ctxt.BuildMode == ld.BuildModeCArchive || ctxt.BuildMode == ld.BuildModeCShared || ctxt.BuildMode == ld.BuildModePIE {
					gentramppic(ctxt.Arch, trampb, rs, int64(offset))
				} else {
					gentramp(ctxt.Arch, ctxt.LinkMode, ldr, trampb, rs, int64(offset))
				}
			}
			// modify reloc to point to tramp, which will be resolved later
			sb := ldr.MakeSymbolUpdater(s)
			relocs := sb.Relocs()
			r := relocs.At(ri)
			r.SetSym(tramp)
			r.SetAdd(r.Add()&0xff000000 | 0xfffffe) // clear the offset embedded in the instruction
		}
	default:
		ctxt.Errorf(s, "trampoline called with non-jump reloc: %d (%s)", r.Type(), sym.RelocName(ctxt.Arch, r.Type()))
	}
}

// generate a trampoline to target+offset.
func gentramp(arch *sys.Arch, linkmode ld.LinkMode, ldr *loader.Loader, tramp *loader.SymbolBuilder, target loader.Sym, offset int64) {
	tramp.SetSize(12) // 3 instructions
	P := make([]byte, tramp.Size())
	t := ldr.SymValue(target) + offset
	o1 := uint32(0xe5900000 | 12<<12 | 15<<16) // MOVW (R15), R12 // R15 is actual pc + 8
	o2 := uint32(0xe12fff10 | 12)              // JMP  (R12)
	o3 := uint32(t)                            // WORD $target
	arch.ByteOrder.PutUint32(P, o1)
	arch.ByteOrder.PutUint32(P[4:], o2)
	arch.ByteOrder.PutUint32(P[8:], o3)
	tramp.SetData(P)

	if linkmode == ld.LinkExternal || ldr.SymValue(target) == 0 {
		r, _ := tramp.AddRel(objabi.R_ADDR)
		r.SetOff(8)
		r.SetSiz(4)
		r.SetSym(target)
		r.SetAdd(offset)
	}
}

// generate a trampoline to target+offset in position independent code.
func gentramppic(arch *sys.Arch, tramp *loader.SymbolBuilder, target loader.Sym, offset int64) {
	tramp.SetSize(16) // 4 instructions
	P := make([]byte, tramp.Size())
	o1 := uint32(0xe5900000 | 12<<12 | 15<<16 | 4)  // MOVW 4(R15), R12 // R15 is actual pc + 8
	o2 := uint32(0xe0800000 | 12<<12 | 15<<16 | 12) // ADD R15, R12, R12
	o3 := uint32(0xe12fff10 | 12)                   // JMP  (R12)
	o4 := uint32(0)                                 // WORD $(target-pc) // filled in with relocation
	arch.ByteOrder.PutUint32(P, o1)
	arch.ByteOrder.PutUint32(P[4:], o2)
	arch.ByteOrder.PutUint32(P[8:], o3)
	arch.ByteOrder.PutUint32(P[12:], o4)
	tramp.SetData(P)

	r, _ := tramp.AddRel(objabi.R_PCREL)
	r.SetOff(12)
	r.SetSiz(4)
	r.SetSym(target)
	r.SetAdd(offset + 4)
}

// generate a trampoline to target+offset in dynlink mode (using GOT).
func gentrampdyn(arch *sys.Arch, tramp *loader.SymbolBuilder, target loader.Sym, offset int64) {
	tramp.SetSize(20)                               // 5 instructions
	o1 := uint32(0xe5900000 | 12<<12 | 15<<16 | 8)  // MOVW 8(R15), R12 // R15 is actual pc + 8
	o2 := uint32(0xe0800000 | 12<<12 | 15<<16 | 12) // ADD R15, R12, R12
	o3 := uint32(0xe5900000 | 12<<12 | 12<<16)      // MOVW (R12), R12
	o4 := uint32(0xe12fff10 | 12)                   // JMP  (R12)
	o5 := uint32(0)                                 // WORD $target@GOT // filled in with relocation
	o6 := uint32(0)
	if offset != 0 {
		// insert an instruction to add offset
		tramp.SetSize(24) // 6 instructions
		o6 = o5
		o5 = o4
		o4 = 0xe2800000 | 12<<12 | 12<<16 | immrot(uint32(offset)) // ADD $offset, R12, R12
		o1 = uint32(0xe5900000 | 12<<12 | 15<<16 | 12)             // MOVW 12(R15), R12
	}
	P := make([]byte, tramp.Size())
	arch.ByteOrder.PutUint32(P, o1)
	arch.ByteOrder.PutUint32(P[4:], o2)
	arch.ByteOrder.PutUint32(P[8:], o3)
	arch.ByteOrder.PutUint32(P[12:], o4)
	arch.ByteOrder.PutUint32(P[16:], o5)
	if offset != 0 {
		arch.ByteOrder.PutUint32(P[20:], o6)
	}
	tramp.SetData(P)

	r, _ := tramp.AddRel(objabi.R_GOTPCREL)
	r.SetOff(16)
	r.SetSiz(4)
	r.SetSym(target)
	r.SetAdd(8)
	if offset != 0 {
		// increase reloc offset by 4 as we inserted an ADD instruction
		r.SetOff(20)
		r.SetAdd(12)
	}
}

func archreloc(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, r loader.Reloc, s loader.Sym, val int64) (o int64, nExtReloc int, ok bool) {
	rs := r.Sym()
	if target.IsExternal() {
		switch r.Type() {
		case objabi.R_CALLARM:
			// set up addend for eventual relocation via outer symbol.
			_, off := ld.FoldSubSymbolOffset(ldr, rs)
			xadd := int64(signext24(r.Add()&0xffffff))*4 + off
			if xadd/4 > 0x7fffff || xadd/4 < -0x800000 {
				ldr.Errorf(s, "direct call too far %d", xadd/4)
			}
			return int64(braddoff(int32(0xff000000&uint32(r.Add())), int32(0xffffff&uint32(xadd/4)))), 1, true
		}
		return -1, 0, false
	}

	const isOk = true
	const noExtReloc = 0
	switch r.Type() {
	// The following three arch specific relocations are only for generation of
	// Linux/ARM ELF's PLT entry (3 assembler instruction)
	case objabi.R_PLT0: // add ip, pc, #0xXX00000
		if ldr.SymValue(syms.GOTPLT) < ldr.SymValue(syms.PLT) {
			ldr.Errorf(s, ".got.plt should be placed after .plt section.")
		}
		return 0xe28fc600 + (0xff & (int64(uint32(ldr.SymValue(rs)-(ldr.SymValue(syms.PLT)+int64(r.Off()))+r.Add())) >> 20)), noExtReloc, isOk
	case objabi.R_PLT1: // add ip, ip, #0xYY000
		return 0xe28cca00 + (0xff & (int64(uint32(ldr.SymValue(rs)-(ldr.SymValue(syms.PLT)+int64(r.Off()))+r.Add()+4)) >> 12)), noExtReloc, isOk
	case objabi.R_PLT2: // ldr pc, [ip, #0xZZZ]!
		return 0xe5bcf000 + (0xfff & int64(uint32(ldr.SymValue(rs)-(ldr.SymValue(syms.PLT)+int64(r.Off()))+r.Add()+8))), noExtReloc, isOk
	case objabi.R_CALLARM: // bl XXXXXX or b YYYYYY
		// r.Add is the instruction
		// low 24-bit encodes the target address
		t := (ldr.SymValue(rs) + int64(signext24(r.Add()&0xffffff)*4) - (ldr.SymValue(s) + int64(r.Off()))) / 4
		if t > 0x7fffff || t < -0x800000 {
			ldr.Errorf(s, "direct call too far: %s %x", ldr.SymName(rs), t)
		}
		return int64(braddoff(int32(0xff000000&uint32(r.Add())), int32(0xffffff&t))), noExtReloc, isOk
	}

	return val, 0, false
}

func archrelocvariant(*ld.Target, *loader.Loader, loader.Reloc, sym.RelocVariant, loader.Sym, int64, []byte) int64 {
	log.Fatalf("unexpected relocation variant")
	return -1
}

func extreloc(target *ld.Target, ldr *loader.Loader, r loader.Reloc, s loader.Sym) (loader.ExtReloc, bool) {
	rs := r.Sym()
	var rr loader.ExtReloc
	switch r.Type() {
	case objabi.R_CALLARM:
		// set up addend for eventual relocation via outer symbol.
		rs, off := ld.FoldSubSymbolOffset(ldr, rs)
		rr.Xadd = int64(signext24(r.Add()&0xffffff))*4 + off
		rst := ldr.SymType(rs)
		if rst != sym.SHOSTOBJ && rst != sym.SDYNIMPORT && rst != sym.SUNDEFEXT && ldr.SymSect(rs) == nil {
			ldr.Errorf(s, "missing section for %s", ldr.SymName(rs))
		}
		rr.Xsym = rs
		rr.Type = r.Type()
		rr.Size = r.Siz()
		return rr, true
	}
	return rr, false
}

func addpltreloc(ldr *loader.Loader, plt *loader.SymbolBuilder, got *loader.SymbolBuilder, s loader.Sym, typ objabi.RelocType) {
	r, _ := plt.AddRel(typ)
	r.SetSym(got.Sym())
	r.SetOff(int32(plt.Size()))
	r.SetSiz(4)
	r.SetAdd(int64(ldr.SymGot(s)) - 8)

	plt.SetReachable(true)
	plt.SetSize(plt.Size() + 4)
	plt.Grow(plt.Size())
}

func addpltsym(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym) {
	if ldr.SymPlt(s) >= 0 {
		return
	}

	ld.Adddynsym(ldr, target, syms, s)

	if target.IsElf() {
		plt := ldr.MakeSymbolUpdater(syms.PLT)
		got := ldr.MakeSymbolUpdater(syms.GOTPLT)
		rel := ldr.MakeSymbolUpdater(syms.RelPLT)
		if plt.Size() == 0 {
			panic("plt is not set up")
		}

		// .got entry
		ldr.SetGot(s, int32(got.Size()))

		// In theory, all GOT should point to the first PLT entry,
		// Linux/ARM's dynamic linker will do that for us, but FreeBSD/ARM's
		// dynamic linker won't, so we'd better do it ourselves.
		got.AddAddrPlus(target.Arch, plt.Sym(), 0)

		// .plt entry, this depends on the .got entry
		ldr.SetPlt(s, int32(plt.Size()))

		addpltreloc(ldr, plt, got, s, objabi.R_PLT0) // add lr, pc, #0xXX00000
		addpltreloc(ldr, plt, got, s, objabi.R_PLT1) // add lr, lr, #0xYY000
		addpltreloc(ldr, plt, got, s, objabi.R_PLT2) // ldr pc, [lr, #0xZZZ]!

		// rel
		rel.AddAddrPlus(target.Arch, got.Sym(), int64(ldr.SymGot(s)))

		rel.AddUint32(target.Arch, elf.R_INFO32(uint32(ldr.SymDynid(s)), uint32(elf.R_ARM_JUMP_SLOT)))
	} else {
		ldr.Errorf(s, "addpltsym: unsupported binary format")
	}
}

func addgotsyminternal(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym) {
	if ldr.SymGot(s) >= 0 {
		return
	}

	got := ldr.MakeSymbolUpdater(syms.GOT)
	ldr.SetGot(s, int32(got.Size()))
	got.AddAddrPlus(target.Arch, s, 0)

	if target.IsElf() {
	} else {
		ldr.Errorf(s, "addgotsyminternal: unsupported binary format")
	}
}
```