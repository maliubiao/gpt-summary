Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding & Context:**

The first step is to acknowledge the file path: `go/src/cmd/link/internal/riscv64/asm.go`. This immediately tells us:

* **Language:** Go
* **Component:** Part of the Go toolchain's linker (`cmd/link`).
* **Architecture:** Specifically for the RISC-V 64-bit architecture (`riscv64`).
* **Functionality:** Related to assembly (`asm.go`), likely dealing with low-level code generation and linking for RISC-V.

**2. High-Level Structure Examination:**

Next, I would quickly scan the top-level declarations and function signatures:

* `package riscv64`: Confirms the architecture scope.
* `import (...)`:  Lists dependencies. These are crucial for understanding what functionalities are being leveraged (e.g., `cmd/internal/obj/riscv` for RISC-V instruction encoding, `cmd/link/internal/ld` for linker data structures, `debug/elf` for ELF file format).
* `const fakeLabelName`:  A string constant, likely used internally.
* `func gentext(...)`:  An empty function. This is interesting – why is it there and empty? It might be a placeholder or have conditional implementation.
* Multiple functions like `findHI20Reloc`, `adddynrel`, `genSymsLate`, `findHI20Symbol`, `elfreloc1`, `elfsetupplt`, `addpltsym`, `machoreloc1`, `archreloc`, `archrelocvariant`, `extreloc`, `trampoline`, `genCallTramp`. The names themselves suggest various stages of the linking process: relocation, dynamic linking, symbol management, and trampoline generation.

**3. Function-by-Function Analysis (Iterative Deepening):**

Now, I would go through each function, trying to understand its purpose.

* **`gentext`:**  Empty. Hypothesis:  Might be used for architecture-specific code generation in other architectures but not needed for RISC-V in this stage, or perhaps it's called elsewhere and this specific file doesn't contribute to it.

* **`findHI20Reloc`:** The name suggests it's searching for a specific type of relocation (`HI20`) within a symbol's relocations. The logic involves iterating through relocations, comparing offsets, and checking relocation types (`R_RISCV_GOT_HI20`, `R_RISCV_PCREL_HI20`). This hints at the handling of addressing modes for RISC-V.

* **`adddynrel`:**  The name suggests adding dynamic relocations. The `switch` statement on `r.Type()` indicates it handles different RISC-V relocation types for dynamic linking. The code deals with PLT (Procedure Linkage Table) entries and GOT (Global Offset Table) entries, common elements in dynamic linking. The `SDYNIMPORT` check is a strong indicator of handling external symbols.

* **`genSymsLate`:** This seems to generate symbols late in the linking process. The comment about `R_RISCV_PCREL_LO12_*` needing local text symbols is a crucial piece of information. The code iterates through text symbols and their relocations, creating new local symbols if necessary. The use of `fakeLabelName` becomes clear here.

* **`findHI20Symbol`:**  Looks for a text symbol at a specific value, likely related to the `HI20` relocations.

* **`elfreloc1`:**  The name suggests handling ELF relocations. The `switch` statement on `r.Type` again shows handling of various RISC-V specific ELF relocation types. The code writes data to an `OutBuf`, implying it's involved in generating the output ELF file. The handling of `R_RISCV_CALL`, `R_RISCV_PCREL_ITYPE`, `R_RISCV_PCREL_STYPE`, and `R_RISCV_TLS_IE` by emitting *two* relocations (HI20 and LO12) is a key detail of RISC-V's addressing modes.

* **`elfsetupplt`:**  This sets up the PLT. The inline assembly-like comments are a huge clue to the structure of the PLT entry on RISC-V. The code adds symbol references and raw bytes to the PLT and GOTPLT.

* **`addpltsym`:** Adds a symbol to the PLT. The code again uses inline assembly comments to show the structure of a PLT entry. It adds entries to the GOTPLT and RelaPLT as well.

* **`machoreloc1`:**  Not implemented. Indicates this code is specifically for ELF, not Mach-O.

* **`archreloc`:**  Handles architecture-specific relocation logic for internal linking. The `switch` statement deals with encoding instruction immediates based on the relocation type. The handling of `R_RISCV_JAL_TRAMP` and the potential for switching to `R_RISCV_JAL` is important.

* **`archrelocvariant`:** Not implemented.

* **`extreloc`:**  Handles relocations for external linking. It differentiates between simple relocations and those requiring the outer symbol.

* **`trampoline`:** Deals with generating or reusing trampolines when direct calls are out of range. The logic for checking reachability and creating new trampolines is present.

* **`genCallTramp`:** Generates the actual code for a call trampoline.

**4. Identifying Key Concepts and Functionality:**

By analyzing the functions, I could identify the core functionalities:

* **Relocation Handling:**  The code extensively handles different RISC-V relocation types, both for internal and external linking.
* **Dynamic Linking Support:** Functions like `adddynrel`, `elfsetupplt`, and `addpltsym` clearly indicate support for dynamic linking through PLT and GOT.
* **Instruction Encoding:** `archreloc` shows how the linker encodes RISC-V instruction immediates based on relocation information.
* **Trampoline Generation:** The `trampoline` and `genCallTramp` functions handle cases where direct calls are not possible due to address range limitations.
* **Symbol Management:** Functions like `genSymsLate`, `findHI20Symbol`, and the use of `loader.SymbolBuilder` are related to managing symbols during the linking process.
* **ELF File Generation:**  `elfreloc1` directly contributes to the generation of ELF relocation entries.

**5. Constructing Examples and Explanations:**

Once I had a good grasp of the functionalities, I started thinking about how to illustrate them with examples. For instance, understanding the purpose of `adddynrel` and `addpltsym` led to the dynamic linking example. Recognizing the instruction encoding in `archreloc` led to the direct call vs. trampoline example.

**6. Identifying Potential Pitfalls:**

Based on the code and my understanding of linking, I could identify potential errors:

* **Incorrect Addends:**  The checks for non-zero addends in `adddynrel` for certain relocation types point to this as a potential issue.
* **Missing HI20 Relocations:** The error check in `archreloc` for `R_RISCV_PCREL_LO12_I/S` highlights the dependency between HI20 and LO12 relocations.

**7. Iteration and Refinement:**

Throughout this process, I would revisit parts of the code, refine my understanding, and adjust my explanations and examples as needed. For instance, initially, I might not have fully grasped the HI20/LO12 relocation pairing, but as I analyzed `elfreloc1` and `archreloc` more closely, the pattern would become clear.

This iterative and analytical approach allows for a comprehensive understanding of even complex code snippets like the one provided. The key is to break down the problem into smaller parts, understand the purpose of each part, and then piece together the bigger picture.
这段Go语言代码是Go链接器（`cmd/link`）中专门处理RISC-V 64位架构（`riscv64`）汇编和链接的部分。它负责将Go代码编译生成的RISC-V目标文件链接成最终的可执行文件或共享库。

以下是代码中各个函数的功能：

**核心功能:**

1. **`gentext(ctxt *ld.Link, ldr *loader.Loader)`:**  目前为空函数。在链接过程中，`gentext` 通常用于生成一些额外的代码段，例如用于支持特定的运行时功能。对于RISC-V 64位架构，在这个阶段可能不需要生成额外的代码。

2. **`findHI20Reloc(ldr *loader.Loader, s loader.Sym, val int64) *loader.Reloc`:**  在给定的符号 `s` 的外部符号（outer symbol）的重定位信息中，查找地址与 `val` 匹配并且类型是 `R_RISCV_GOT_HI20` 或 `R_RISCV_PCREL_HI20` 的重定位项。这用于查找与后续LO12类型重定位配对的HI20类型重定位，这是RISC-V处理大偏移地址的一种方式。

3. **`adddynrel(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym, r loader.Reloc, rIdx int) bool`:** 处理动态链接相关的重定位。根据不同的RISC-V ELF重定位类型，例如函数调用、GOT (Global Offset Table) 条目的加载等，它会执行相应的操作，例如添加PLT (Procedure Linkage Table) 条目、更新重定位类型和目标符号等。

4. **`genSymsLate(ctxt *ld.Link, ldr *loader.Loader)`:** 在链接的后期阶段生成一些额外的符号。特别地，对于外部链接模式，它会为每个重定位目标生成一个本地的文本符号，用于支持 `R_RISCV_PCREL_LO12_*` 类型的重定位。这些符号充当临时标签，方便计算相对于代码位置的偏移。

5. **`findHI20Symbol(ctxt *ld.Link, ldr *loader.Loader, val int64) loader.Sym`:**  在 `.text` 代码段中查找地址与 `val` 匹配的文本符号。这与 `findHI20Reloc` 配合使用，确保在生成LO12重定位时能找到对应的HI20重定位的符号。

6. **`elfreloc1(ctxt *ld.Link, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, ri int, sectoff int64) bool`:**  处理生成ELF格式的重定位信息。它根据不同的Go重定位类型（`objabi.R_*`）将其转换为对应的RISC-V ELF重定位类型（`elf.R_RISCV_*`），并将重定位信息写入输出缓冲区。这包括处理例如绝对地址、函数调用、PC相对寻址以及TLS相关的重定位。对于像 `R_RISCV_CALL` 这样的PC相对调用，它会生成一对 HI20 和 LO12 的重定位。

7. **`elfsetupplt(ctxt *ld.Link, ldr *loader.Loader, plt, gotplt *loader.SymbolBuilder, dynamic loader.Sym)`:**  设置PLT (Procedure Linkage Table)。PLT用于延迟绑定动态链接的函数。此函数会向 `.plt` 和 `.got.plt` 段添加代码和数据，实现PLT的基本结构，用于在运行时解析外部函数。

8. **`addpltsym(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym)`:**  向PLT添加一个符号的条目。当链接器遇到对动态链接符号的引用时，会调用此函数在PLT中创建一个条目，以便在运行时调用该符号。

9. **`machoreloc1(*sys.Arch, *ld.OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool`:**  声明了 `machoreloc1` 函数，但其内部调用了 `log.Fatalf`，表明 RISC-V 64位架构的链接器实现目前不支持 Mach-O 格式。

10. **`archreloc(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, r loader.Reloc, s loader.Sym, val int64) (o int64, nExtReloc int, ok bool)`:**  处理架构相关的重定位。对于内部链接，它会根据重定位类型计算并应用实际的偏移量，例如计算JAL指令的立即数、处理TLS相关的重定位等。对于外部链接，它会标记需要外部链接器处理的重定位。

11. **`archrelocvariant(*ld.Target, *loader.Loader, loader.Reloc, sym.RelocVariant, loader.Sym, int64, []byte) int64`:**  声明了 `archrelocvariant` 函数，但其内部调用了 `log.Fatalf`，表明该变体的重定位处理尚未实现。

12. **`extreloc(target *ld.Target, ldr *loader.Loader, r loader.Reloc, s loader.Sym) (loader.ExtReloc, bool)`:**  确定是否需要为给定的重定位创建外部重定位记录。这通常用于外部链接器需要处理的重定位类型。

13. **`trampoline(ctxt *ld.Link, ldr *loader.Loader, ri int, rs, s loader.Sym)`:**  处理跳转指令的目标地址超出直接寻址范围的情况。它会创建或重用一个跳转跳板（trampoline），使得可以通过短跳转先跳转到跳板，再从跳板跳转到目标地址。这对于解决远距离调用问题非常重要。

14. **`genCallTramp(arch *sys.Arch, linkmode ld.LinkMode, ldr *loader.Loader, tramp *loader.SymbolBuilder, target loader.Sym, offset int64)`:**  生成实际的调用跳板代码。跳板通常包含加载目标地址到寄存器并执行间接跳转的指令序列。

**它是什么Go语言功能的实现？**

这段代码是 Go 语言链接器中 **处理 RISC-V 64位架构目标文件链接** 的核心部分。它实现了以下关键的链接功能：

* **符号解析和重定位:** 将程序中对符号的引用绑定到它们在内存中的实际地址。
* **动态链接支持:**  生成必要的PLT和GOT条目，以便程序在运行时可以调用共享库中的函数。
* **代码布局和节区管理:**  确定代码和数据在最终可执行文件中的位置。
* **指令编码:**  根据目标地址计算并编码 RISC-V 指令的立即数。
* **跳转范围扩展:**  通过生成跳转跳板来克服 RISC-V 指令的跳转范围限制。

**Go代码举例说明 (涉及代码推理):**

假设我们有以下简单的 Go 代码：

```go
package main

import "fmt"

func externalFunc()

func main() {
	fmt.Println("Hello, RISC-V!")
	externalFunc()
}
```

并且 `externalFunc` 定义在另一个编译单元或共享库中。

**假设的输入 (编译后的目标文件):**

在编译 `main.go` 后，生成的 RISC-V 目标文件中，对 `fmt.Println` 和 `externalFunc` 的调用处会包含需要链接器处理的重定位信息。例如，对 `externalFunc` 的调用可能包含一个类型为 `objabi.R_RISCV_CALL` 的重定位项，指示需要进行函数调用。

**代码推理和 `adddynrel` 的作用:**

当链接器处理到对 `externalFunc` 的调用时，`adddynrel` 函数会被调用。由于 `externalFunc` 不是在当前的编译单元中定义的，它的类型可能是 `sym.SDYNIMPORT` (动态导入的符号)。

`adddynrel` 函数会检查重定位类型 `r.Type()`。如果它是与函数调用相关的动态重定位类型（例如 `objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_CALL)` 或 `objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_CALL_PLT)`），并且目标符号 `targ` 是动态导入的，`adddynrel` 会执行以下操作：

1. **`addpltsym(target, ldr, syms, targ)`:**  调用 `addpltsym` 在 PLT 中为 `externalFunc` 创建一个条目。
2. **`su := ldr.MakeSymbolUpdater(s)`:** 获取当前符号 `s` 的更新器。
3. **`su.SetRelocSym(rIdx, syms.PLT)`:** 将当前重定位项的目标符号设置为 PLT 表的符号。
4. **`su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymPlt(targ)))`:** 更新重定位的附加值，使其指向 `externalFunc` 在 PLT 中的具体偏移量。
5. **`su.SetRelocType(rIdx, objabi.R_RISCV_CALL)`:**  最终将重定位类型设置为 `objabi.R_RISCV_CALL`，表示一个普通的函数调用（可能在内部链接时会进一步处理）。

**假设的输出 (链接后的可执行文件):**

链接后的可执行文件中，`.plt` 段会包含 `externalFunc` 的条目。当程序执行到调用 `externalFunc` 的地方时，实际上会跳转到 PLT 中相应的条目。PLT 条目中的代码会负责在运行时解析 `externalFunc` 的实际地址，并跳转到该地址执行。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理发生在 `cmd/link/internal/ld` 包中的更上层代码中。例如，命令行参数 `-buildmode=...` 会影响链接模式，进而影响 `adddynrel` 等函数的行为（例如，是否需要生成 PLT 条目）。

**使用者易犯错的点:**

这段代码是链接器的内部实现，普通 Go 开发者不会直接与之交互，因此不易犯错。然而，对于需要深入了解链接过程或开发底层工具链的开发者来说，理解 RISC-V 的重定位类型和 PLT/GOT 的工作原理至关重要。

一个潜在的“错误”理解是 **假设所有函数调用都是直接跳转**。在动态链接的情况下，对外部函数的调用会经过 PLT，这会增加一层间接性。如果对链接过程不熟悉，可能会对程序执行的流程产生误解。

另一个点是 **对 HI20 和 LO12 重定位的理解**。RISC-V 使用这种机制来处理 32 位的地址偏移。初学者可能会困惑为什么一个地址需要两个重定位来表示。例如，在 `elfreloc1` 中处理 `R_RISCV_CALL` 时，会生成 `R_RISCV_PCREL_HI20` 和 `R_RISCV_PCREL_LO12_I` 两个重定位，分别用于加载地址的高 20 位和低 12 位。

总而言之，这段代码是 Go 链接器为 RISC-V 64位架构量身定制的关键组成部分，负责将编译后的代码片段组装成可执行的程序，并处理动态链接和架构特定的指令编码等细节。理解这段代码有助于深入了解 Go 语言的底层编译和链接过程。

Prompt: 
```
这是路径为go/src/cmd/link/internal/riscv64/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package riscv64

import (
	"cmd/internal/obj/riscv"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/ld"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/elf"
	"fmt"
	"log"
	"sort"
)

// fakeLabelName matches the RISCV_FAKE_LABEL_NAME from binutils.
const fakeLabelName = ".L0 "

func gentext(ctxt *ld.Link, ldr *loader.Loader) {}

func findHI20Reloc(ldr *loader.Loader, s loader.Sym, val int64) *loader.Reloc {
	outer := ldr.OuterSym(s)
	if outer == 0 {
		return nil
	}
	relocs := ldr.Relocs(outer)
	start := sort.Search(relocs.Count(), func(i int) bool { return ldr.SymValue(outer)+int64(relocs.At(i).Off()) >= val })
	for idx := start; idx < relocs.Count(); idx++ {
		r := relocs.At(idx)
		if ldr.SymValue(outer)+int64(r.Off()) != val {
			break
		}
		if r.Type() == objabi.R_RISCV_GOT_HI20 || r.Type() == objabi.R_RISCV_PCREL_HI20 {
			return &r
		}
	}
	return nil
}

func adddynrel(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym, r loader.Reloc, rIdx int) bool {
	targ := r.Sym()

	var targType sym.SymKind
	if targ != 0 {
		targType = ldr.SymType(targ)
	}

	switch r.Type() {
	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_CALL),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_CALL_PLT):

		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			su := ldr.MakeSymbolUpdater(s)
			su.SetRelocSym(rIdx, syms.PLT)
			su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymPlt(targ)))
		}
		if targType == 0 || targType == sym.SXREF {
			ldr.Errorf(s, "unknown symbol %s in RISCV call", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_RISCV_CALL)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_GOT_HI20):
		if targType != sym.SDYNIMPORT {
			// TODO(jsing): Could convert to non-GOT reference.
		}

		ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_RISCV_64))
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_RISCV_GOT_HI20)
		su.SetRelocSym(rIdx, syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymGot(targ)))
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_PCREL_HI20):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_RISCV_PCREL_HI20)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_PCREL_LO12_I):
		if r.Add() != 0 {
			ldr.Errorf(s, "R_RISCV_PCREL_LO12_I with non-zero addend")
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_RISCV_PCREL_LO12_I)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_PCREL_LO12_S):
		if r.Add() != 0 {
			ldr.Errorf(s, "R_RISCV_PCREL_LO12_S with non-zero addend")
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_RISCV_PCREL_LO12_S)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_RVC_BRANCH):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_RISCV_RVC_BRANCH)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_RVC_JUMP):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_RISCV_RVC_JUMP)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_BRANCH):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_RISCV_BRANCH)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_RISCV_RELAX):
		// Ignore relaxations, at least for now.
		return true

	default:
		if r.Type() >= objabi.ElfRelocOffset {
			ldr.Errorf(s, "unexpected relocation type %d (%s)", r.Type(), sym.RelocName(target.Arch, r.Type()))
			return false
		}
	}

	// Reread the reloc to incorporate any changes in type above.
	relocs := ldr.Relocs(s)
	r = relocs.At(rIdx)

	switch r.Type() {
	case objabi.R_RISCV_CALL:
		if targType != sym.SDYNIMPORT {
			// nothing to do, the relocation will be laid out in reloc
			return true
		}
		if target.IsExternal() {
			// External linker will do this relocation.
			return true
		}
		// Internal linking.
		if r.Add() != 0 {
			ldr.Errorf(s, "PLT reference with non-zero addend (%v)", r.Add())
		}
		// Build a PLT entry and change the relocation target to that entry.
		addpltsym(target, ldr, syms, targ)
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocSym(rIdx, syms.PLT)
		su.SetRelocAdd(rIdx, int64(ldr.SymPlt(targ)))

		return true
	}

	return false
}

func genSymsLate(ctxt *ld.Link, ldr *loader.Loader) {
	if ctxt.LinkMode != ld.LinkExternal {
		return
	}

	// Generate a local text symbol for each relocation target, as the
	// R_RISCV_PCREL_LO12_* relocations generated by elfreloc1 need it.
	if ctxt.Textp == nil {
		log.Fatal("genSymsLate called before Textp has been assigned")
	}
	var hi20Syms []loader.Sym
	for _, s := range ctxt.Textp {
		relocs := ldr.Relocs(s)
		for ri := 0; ri < relocs.Count(); ri++ {
			r := relocs.At(ri)
			if r.Type() != objabi.R_RISCV_CALL && r.Type() != objabi.R_RISCV_PCREL_ITYPE &&
				r.Type() != objabi.R_RISCV_PCREL_STYPE && r.Type() != objabi.R_RISCV_TLS_IE {
				continue
			}
			if r.Off() == 0 && ldr.SymType(s).IsText() {
				// Use the symbol for the function instead of creating
				// an overlapping symbol.
				continue
			}

			// TODO(jsing): Consider generating ELF symbols without needing
			// loader symbols, in order to reduce memory consumption. This
			// would require changes to genelfsym so that it called
			// putelfsym and putelfsyment as appropriate.
			sb := ldr.MakeSymbolBuilder(fakeLabelName)
			sb.SetType(sym.STEXT)
			sb.SetValue(ldr.SymValue(s) + int64(r.Off()))
			sb.SetLocal(true)
			sb.SetReachable(true)
			sb.SetVisibilityHidden(true)
			sb.SetSect(ldr.SymSect(s))
			if outer := ldr.OuterSym(s); outer != 0 {
				ldr.AddInteriorSym(outer, sb.Sym())
			}
			hi20Syms = append(hi20Syms, sb.Sym())
		}
	}
	ctxt.Textp = append(ctxt.Textp, hi20Syms...)
	ldr.SortSyms(ctxt.Textp)
}

func findHI20Symbol(ctxt *ld.Link, ldr *loader.Loader, val int64) loader.Sym {
	idx := sort.Search(len(ctxt.Textp), func(i int) bool { return ldr.SymValue(ctxt.Textp[i]) >= val })
	if idx >= len(ctxt.Textp) {
		return 0
	}
	if s := ctxt.Textp[idx]; ldr.SymValue(s) == val && ldr.SymType(s).IsText() {
		return s
	}
	return 0
}

func elfreloc1(ctxt *ld.Link, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, ri int, sectoff int64) bool {
	elfsym := ld.ElfSymForReloc(ctxt, r.Xsym)
	switch r.Type {
	case objabi.R_ADDR, objabi.R_DWARFSECREF:
		out.Write64(uint64(sectoff))
		switch r.Size {
		case 4:
			out.Write64(uint64(elf.R_RISCV_32) | uint64(elfsym)<<32)
		case 8:
			out.Write64(uint64(elf.R_RISCV_64) | uint64(elfsym)<<32)
		default:
			ld.Errorf("unknown size %d for %v relocation", r.Size, r.Type)
			return false
		}
		out.Write64(uint64(r.Xadd))

	case objabi.R_RISCV_JAL, objabi.R_RISCV_JAL_TRAMP:
		out.Write64(uint64(sectoff))
		out.Write64(uint64(elf.R_RISCV_JAL) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))

	case objabi.R_RISCV_CALL, objabi.R_RISCV_PCREL_ITYPE, objabi.R_RISCV_PCREL_STYPE, objabi.R_RISCV_TLS_IE:
		// Find the text symbol for the AUIPC instruction targeted
		// by this relocation.
		relocs := ldr.Relocs(s)
		offset := int64(relocs.At(ri).Off())
		hi20Sym := findHI20Symbol(ctxt, ldr, ldr.SymValue(s)+offset)
		if hi20Sym == 0 {
			ld.Errorf("failed to find text symbol for HI20 relocation at %d (%x)", sectoff, ldr.SymValue(s)+offset)
			return false
		}
		hi20ElfSym := ld.ElfSymForReloc(ctxt, hi20Sym)

		// Emit two relocations - a R_RISCV_PCREL_HI20 relocation and a
		// corresponding R_RISCV_PCREL_LO12_I or R_RISCV_PCREL_LO12_S relocation.
		// Note that the LO12 relocation must point to a target that has a valid
		// HI20 PC-relative relocation text symbol, which in turn points to the
		// given symbol. For further details see section 8.4.9 of the RISC-V ABIs
		// Specification:
		//
		//  https://github.com/riscv-non-isa/riscv-elf-psabi-doc/releases/download/v1.0/riscv-abi.pdf
		//
		var hiRel, loRel elf.R_RISCV
		switch r.Type {
		case objabi.R_RISCV_CALL, objabi.R_RISCV_PCREL_ITYPE:
			hiRel, loRel = elf.R_RISCV_PCREL_HI20, elf.R_RISCV_PCREL_LO12_I
		case objabi.R_RISCV_PCREL_STYPE:
			hiRel, loRel = elf.R_RISCV_PCREL_HI20, elf.R_RISCV_PCREL_LO12_S
		case objabi.R_RISCV_TLS_IE:
			hiRel, loRel = elf.R_RISCV_TLS_GOT_HI20, elf.R_RISCV_PCREL_LO12_I
		}
		out.Write64(uint64(sectoff))
		out.Write64(uint64(hiRel) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(loRel) | uint64(hi20ElfSym)<<32)
		out.Write64(uint64(0))

	case objabi.R_RISCV_TLS_LE:
		out.Write64(uint64(sectoff))
		out.Write64(uint64(elf.R_RISCV_TPREL_HI20) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_RISCV_TPREL_LO12_I) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))

	default:
		return false
	}

	return true
}

func elfsetupplt(ctxt *ld.Link, ldr *loader.Loader, plt, gotplt *loader.SymbolBuilder, dynamic loader.Sym) {
	if plt.Size() != 0 {
		return
	}
	if gotplt.Size() != 0 {
		ctxt.Errorf(gotplt.Sym(), "got.plt is not empty")
	}

	// See section 8.4.6 of the RISC-V ABIs Specification:
	//
	//  https://github.com/riscv-non-isa/riscv-elf-psabi-doc/releases/download/v1.0/riscv-abi.pdf
	//
	// 1:   auipc  t2, %pcrel_hi(.got.plt)
	//      sub    t1, t1, t3               # shifted .got.plt offset + hdr size + 12
	//      l[w|d] t3, %pcrel_lo(1b)(t2)    # _dl_runtime_resolve
	//      addi   t1, t1, -(hdr size + 12) # shifted .got.plt offset
	//      addi   t0, t2, %pcrel_lo(1b)    # &.got.plt
	//      srli   t1, t1, log2(16/PTRSIZE) # .got.plt offset
	//      l[w|d] t0, PTRSIZE(t0)          # link map
	//      jr     t3

	plt.AddSymRef(ctxt.Arch, gotplt.Sym(), 0, objabi.R_RISCV_PCREL_HI20, 4)
	plt.SetUint32(ctxt.Arch, plt.Size()-4, 0x00000397) // auipc   t2,0x0

	sb := ldr.MakeSymbolBuilder(fakeLabelName)
	sb.SetType(sym.STEXT)
	sb.SetValue(ldr.SymValue(plt.Sym()) + plt.Size() - 4)
	sb.SetLocal(true)
	sb.SetReachable(true)
	sb.SetVisibilityHidden(true)
	plt.AddInteriorSym(sb.Sym())

	plt.AddUint32(ctxt.Arch, 0x41c30333) // sub     t1,t1,t3

	plt.AddSymRef(ctxt.Arch, sb.Sym(), 0, objabi.R_RISCV_PCREL_LO12_I, 4)
	plt.SetUint32(ctxt.Arch, plt.Size()-4, 0x0003be03) // ld      t3,0(t2)

	plt.AddUint32(ctxt.Arch, 0xfd430313) // addi    t1,t1,-44

	plt.AddSymRef(ctxt.Arch, sb.Sym(), 0, objabi.R_RISCV_PCREL_LO12_I, 4)
	plt.SetUint32(ctxt.Arch, plt.Size()-4, 0x00038293) // addi    t0,t2,0

	plt.AddUint32(ctxt.Arch, 0x00135313) // srli    t1,t1,0x1
	plt.AddUint32(ctxt.Arch, 0x0082b283) // ld      t0,8(t0)
	plt.AddUint32(ctxt.Arch, 0x00008e02) // jr      t3

	gotplt.AddAddrPlus(ctxt.Arch, dynamic, 0) // got.plt[0] = _dl_runtime_resolve
	gotplt.AddUint64(ctxt.Arch, 0)            // got.plt[1] = link map
}

func addpltsym(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym) {
	if ldr.SymPlt(s) >= 0 {
		return
	}

	ld.Adddynsym(ldr, target, syms, s)

	plt := ldr.MakeSymbolUpdater(syms.PLT)
	gotplt := ldr.MakeSymbolUpdater(syms.GOTPLT)
	rela := ldr.MakeSymbolUpdater(syms.RelaPLT)
	if plt.Size() == 0 {
		panic("plt is not set up")
	}

	// See section 8.4.6 of the RISC-V ABIs Specification:
	//
	//  https://github.com/riscv-non-isa/riscv-elf-psabi-doc/releases/download/v1.0/riscv-abi.pdf
	//
	// 1:  auipc   t3, %pcrel_hi(function@.got.plt)
	//     l[w|d]  t3, %pcrel_lo(1b)(t3)
	//     jalr    t1, t3
	//     nop

	plt.AddSymRef(target.Arch, gotplt.Sym(), gotplt.Size(), objabi.R_RISCV_PCREL_HI20, 4)
	plt.SetUint32(target.Arch, plt.Size()-4, 0x00000e17) // auipc   t3,0x0

	sb := ldr.MakeSymbolBuilder(fakeLabelName)
	sb.SetType(sym.STEXT)
	sb.SetValue(ldr.SymValue(plt.Sym()) + plt.Size() - 4)
	sb.SetLocal(true)
	sb.SetReachable(true)
	sb.SetVisibilityHidden(true)
	plt.AddInteriorSym(sb.Sym())

	plt.AddSymRef(target.Arch, sb.Sym(), 0, objabi.R_RISCV_PCREL_LO12_I, 4)
	plt.SetUint32(target.Arch, plt.Size()-4, 0x000e3e03) // ld      t3,0(t3)
	plt.AddUint32(target.Arch, 0x000e0367)               // jalr    t1,t3
	plt.AddUint32(target.Arch, 0x00000001)               // nop

	ldr.SetPlt(s, int32(plt.Size()-16))

	// add to got.plt: pointer to plt[0]
	gotplt.AddAddrPlus(target.Arch, plt.Sym(), 0)

	// rela
	rela.AddAddrPlus(target.Arch, gotplt.Sym(), gotplt.Size()-8)
	sDynid := ldr.SymDynid(s)

	rela.AddUint64(target.Arch, elf.R_INFO(uint32(sDynid), uint32(elf.R_RISCV_JUMP_SLOT)))
	rela.AddUint64(target.Arch, 0)
}

func machoreloc1(*sys.Arch, *ld.OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool {
	log.Fatalf("machoreloc1 not implemented")
	return false
}

func archreloc(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, r loader.Reloc, s loader.Sym, val int64) (o int64, nExtReloc int, ok bool) {
	rs := r.Sym()
	pc := ldr.SymValue(s) + int64(r.Off())

	// If the call points to a trampoline, see if we can reach the symbol
	// directly. This situation can occur when the relocation symbol is
	// not assigned an address until after the trampolines are generated.
	if r.Type() == objabi.R_RISCV_JAL_TRAMP {
		relocs := ldr.Relocs(rs)
		if relocs.Count() != 1 {
			ldr.Errorf(s, "trampoline %v has %d relocations", ldr.SymName(rs), relocs.Count())
		}
		tr := relocs.At(0)
		if tr.Type() != objabi.R_RISCV_CALL {
			ldr.Errorf(s, "trampoline %v has unexpected relocation %v", ldr.SymName(rs), tr.Type())
		}
		trs := tr.Sym()
		if ldr.SymValue(trs) != 0 && ldr.SymType(trs) != sym.SDYNIMPORT && ldr.SymType(trs) != sym.SUNDEFEXT {
			trsOff := ldr.SymValue(trs) + tr.Add() - pc
			if trsOff >= -(1<<20) && trsOff < (1<<20) {
				r.SetType(objabi.R_RISCV_JAL)
				r.SetSym(trs)
				r.SetAdd(tr.Add())
				rs = trs
			}
		}

	}

	if target.IsExternal() {
		switch r.Type() {
		case objabi.R_RISCV_JAL, objabi.R_RISCV_JAL_TRAMP:
			return val, 1, true

		case objabi.R_RISCV_CALL, objabi.R_RISCV_PCREL_ITYPE, objabi.R_RISCV_PCREL_STYPE, objabi.R_RISCV_TLS_IE, objabi.R_RISCV_TLS_LE:
			return val, 2, true
		}

		return val, 0, false
	}

	off := ldr.SymValue(rs) + r.Add() - pc

	switch r.Type() {
	case objabi.R_RISCV_JAL, objabi.R_RISCV_JAL_TRAMP:
		// Generate instruction immediates.
		imm, err := riscv.EncodeJImmediate(off)
		if err != nil {
			ldr.Errorf(s, "cannot encode J-type instruction relocation offset for %s: %v", ldr.SymName(rs), err)
		}
		immMask := int64(riscv.JTypeImmMask)

		val = (val &^ immMask) | int64(imm)

		return val, 0, true

	case objabi.R_RISCV_TLS_IE:
		log.Fatalf("cannot handle R_RISCV_TLS_IE (sym %s) when linking internally", ldr.SymName(s))
		return val, 0, false

	case objabi.R_RISCV_TLS_LE:
		// Generate LUI and ADDIW instruction immediates.
		off := r.Add()

		low, high, err := riscv.Split32BitImmediate(off)
		if err != nil {
			ldr.Errorf(s, "relocation does not fit in 32-bits: %d", off)
		}

		luiImm, err := riscv.EncodeUImmediate(high)
		if err != nil {
			ldr.Errorf(s, "cannot encode R_RISCV_TLS_LE LUI relocation offset for %s: %v", ldr.SymName(rs), err)
		}

		addiwImm, err := riscv.EncodeIImmediate(low)
		if err != nil {
			ldr.Errorf(s, "cannot encode R_RISCV_TLS_LE I-type instruction relocation offset for %s: %v", ldr.SymName(rs), err)
		}

		lui := int64(uint32(val))
		addiw := int64(uint32(val >> 32))

		lui = (lui &^ riscv.UTypeImmMask) | int64(uint32(luiImm))
		addiw = (addiw &^ riscv.ITypeImmMask) | int64(uint32(addiwImm))

		return addiw<<32 | lui, 0, true

	case objabi.R_RISCV_BRANCH:
		pc := ldr.SymValue(s) + int64(r.Off())
		off := ldr.SymValue(rs) + r.Add() - pc

		imm, err := riscv.EncodeBImmediate(off)
		if err != nil {
			ldr.Errorf(s, "cannot encode B-type instruction relocation offset for %s: %v", ldr.SymName(rs), err)
		}
		ins := (int64(uint32(val)) &^ riscv.BTypeImmMask) | int64(uint32(imm))

		return ins, 0, true

	case objabi.R_RISCV_RVC_BRANCH, objabi.R_RISCV_RVC_JUMP:
		pc := ldr.SymValue(s) + int64(r.Off())
		off := ldr.SymValue(rs) + r.Add() - pc

		var err error
		var imm, immMask int64
		switch r.Type() {
		case objabi.R_RISCV_RVC_BRANCH:
			immMask = riscv.CBTypeImmMask
			imm, err = riscv.EncodeCBImmediate(off)
			if err != nil {
				ldr.Errorf(s, "cannot encode CB-type instruction relocation offset for %s: %v", ldr.SymName(rs), err)
			}
		case objabi.R_RISCV_RVC_JUMP:
			immMask = riscv.CJTypeImmMask
			imm, err = riscv.EncodeCJImmediate(off)
			if err != nil {
				ldr.Errorf(s, "cannot encode CJ-type instruction relocation offset for %s: %v", ldr.SymName(rs), err)
			}
		default:
			panic(fmt.Sprintf("unknown relocation type: %v", r.Type()))
		}

		ins := (int64(uint16(val)) &^ immMask) | int64(uint16(imm))

		return ins, 0, true

	case objabi.R_RISCV_GOT_HI20, objabi.R_RISCV_PCREL_HI20:
		pc := ldr.SymValue(s) + int64(r.Off())
		off := ldr.SymValue(rs) + r.Add() - pc

		// Generate AUIPC immediates.
		_, high, err := riscv.Split32BitImmediate(off)
		if err != nil {
			ldr.Errorf(s, "relocation does not fit in 32-bits: %d", off)
		}

		auipcImm, err := riscv.EncodeUImmediate(high)
		if err != nil {
			ldr.Errorf(s, "cannot encode R_RISCV_PCREL_ AUIPC relocation offset for %s: %v", ldr.SymName(rs), err)
		}

		auipc := int64(uint32(val))
		auipc = (auipc &^ riscv.UTypeImmMask) | int64(uint32(auipcImm))

		return auipc, 0, true

	case objabi.R_RISCV_PCREL_LO12_I, objabi.R_RISCV_PCREL_LO12_S:
		hi20Reloc := findHI20Reloc(ldr, rs, ldr.SymValue(rs))
		if hi20Reloc == nil {
			ldr.Errorf(s, "missing HI20 relocation for LO12 relocation with %s (%d)", ldr.SymName(rs), rs)
		}

		pc := ldr.SymValue(s) + int64(hi20Reloc.Off())
		off := ldr.SymValue(hi20Reloc.Sym()) + hi20Reloc.Add() - pc

		low, _, err := riscv.Split32BitImmediate(off)
		if err != nil {
			ldr.Errorf(s, "relocation does not fit in 32-bits: %d", off)
		}

		var imm, immMask int64
		switch r.Type() {
		case objabi.R_RISCV_PCREL_LO12_I:
			immMask = riscv.ITypeImmMask
			imm, err = riscv.EncodeIImmediate(low)
			if err != nil {
				ldr.Errorf(s, "cannot encode objabi.R_RISCV_PCREL_LO12_I I-type instruction relocation offset for %s: %v", ldr.SymName(rs), err)
			}
		case objabi.R_RISCV_PCREL_LO12_S:
			immMask = riscv.STypeImmMask
			imm, err = riscv.EncodeSImmediate(low)
			if err != nil {
				ldr.Errorf(s, "cannot encode R_RISCV_PCREL_LO12_S S-type instruction relocation offset for %s: %v", ldr.SymName(rs), err)
			}
		default:
			panic(fmt.Sprintf("unknown relocation type: %v", r.Type()))
		}

		ins := int64(uint32(val))
		ins = (ins &^ immMask) | int64(uint32(imm))
		return ins, 0, true

	case objabi.R_RISCV_CALL, objabi.R_RISCV_PCREL_ITYPE, objabi.R_RISCV_PCREL_STYPE:
		// Generate AUIPC and second instruction immediates.
		low, high, err := riscv.Split32BitImmediate(off)
		if err != nil {
			ldr.Errorf(s, "pc-relative relocation does not fit in 32 bits: %d", off)
		}

		auipcImm, err := riscv.EncodeUImmediate(high)
		if err != nil {
			ldr.Errorf(s, "cannot encode AUIPC relocation offset for %s: %v", ldr.SymName(rs), err)
		}

		var secondImm, secondImmMask int64
		switch r.Type() {
		case objabi.R_RISCV_CALL, objabi.R_RISCV_PCREL_ITYPE:
			secondImmMask = riscv.ITypeImmMask
			secondImm, err = riscv.EncodeIImmediate(low)
			if err != nil {
				ldr.Errorf(s, "cannot encode I-type instruction relocation offset for %s: %v", ldr.SymName(rs), err)
			}
		case objabi.R_RISCV_PCREL_STYPE:
			secondImmMask = riscv.STypeImmMask
			secondImm, err = riscv.EncodeSImmediate(low)
			if err != nil {
				ldr.Errorf(s, "cannot encode S-type instruction relocation offset for %s: %v", ldr.SymName(rs), err)
			}
		default:
			panic(fmt.Sprintf("unknown relocation type: %v", r.Type()))
		}

		auipc := int64(uint32(val))
		second := int64(uint32(val >> 32))

		auipc = (auipc &^ riscv.UTypeImmMask) | int64(uint32(auipcImm))
		second = (second &^ secondImmMask) | int64(uint32(secondImm))

		return second<<32 | auipc, 0, true
	}

	return val, 0, false
}

func archrelocvariant(*ld.Target, *loader.Loader, loader.Reloc, sym.RelocVariant, loader.Sym, int64, []byte) int64 {
	log.Fatalf("archrelocvariant")
	return -1
}

func extreloc(target *ld.Target, ldr *loader.Loader, r loader.Reloc, s loader.Sym) (loader.ExtReloc, bool) {
	switch r.Type() {
	case objabi.R_RISCV_JAL, objabi.R_RISCV_JAL_TRAMP:
		return ld.ExtrelocSimple(ldr, r), true

	case objabi.R_RISCV_CALL, objabi.R_RISCV_PCREL_ITYPE, objabi.R_RISCV_PCREL_STYPE, objabi.R_RISCV_TLS_IE, objabi.R_RISCV_TLS_LE:
		return ld.ExtrelocViaOuterSym(ldr, r, s), true
	}
	return loader.ExtReloc{}, false
}

func trampoline(ctxt *ld.Link, ldr *loader.Loader, ri int, rs, s loader.Sym) {
	relocs := ldr.Relocs(s)
	r := relocs.At(ri)

	switch r.Type() {
	case objabi.R_RISCV_JAL:
		pc := ldr.SymValue(s) + int64(r.Off())
		off := ldr.SymValue(rs) + r.Add() - pc

		// Relocation symbol has an address and is directly reachable,
		// therefore there is no need for a trampoline.
		if ldr.SymValue(rs) != 0 && off >= -(1<<20) && off < (1<<20) && (*ld.FlagDebugTramp <= 1 || ldr.SymPkg(s) == ldr.SymPkg(rs)) {
			break
		}

		// Relocation symbol is too far for a direct call or has not
		// yet been given an address. See if an existing trampoline is
		// reachable and if so, reuse it. Otherwise we need to create
		// a new trampoline.
		var tramp loader.Sym
		for i := 0; ; i++ {
			oName := ldr.SymName(rs)
			name := fmt.Sprintf("%s-tramp%d", oName, i)
			if r.Add() != 0 {
				name = fmt.Sprintf("%s%+x-tramp%d", oName, r.Add(), i)
			}
			tramp = ldr.LookupOrCreateSym(name, int(ldr.SymVersion(rs)))
			ldr.SetAttrReachable(tramp, true)
			if ldr.SymType(tramp) == sym.SDYNIMPORT {
				// Do not reuse trampoline defined in other module.
				continue
			}
			if oName == "runtime.deferreturn" {
				ldr.SetIsDeferReturnTramp(tramp, true)
			}
			if ldr.SymValue(tramp) == 0 {
				// Either trampoline does not exist or we found one
				// that does not have an address assigned and will be
				// laid down immediately after the current function.
				break
			}

			trampOff := ldr.SymValue(tramp) - (ldr.SymValue(s) + int64(r.Off()))
			if trampOff >= -(1<<20) && trampOff < (1<<20) {
				// An existing trampoline that is reachable.
				break
			}
		}
		if ldr.SymType(tramp) == 0 {
			trampb := ldr.MakeSymbolUpdater(tramp)
			ctxt.AddTramp(trampb, ldr.SymType(s))
			genCallTramp(ctxt.Arch, ctxt.LinkMode, ldr, trampb, rs, int64(r.Add()))
		}
		sb := ldr.MakeSymbolUpdater(s)
		if ldr.SymValue(rs) == 0 {
			// In this case the target symbol has not yet been assigned an
			// address, so we have to assume a trampoline is required. Mark
			// this as a call via a trampoline so that we can potentially
			// switch to a direct call during relocation.
			sb.SetRelocType(ri, objabi.R_RISCV_JAL_TRAMP)
		}
		relocs := sb.Relocs()
		r := relocs.At(ri)
		r.SetSym(tramp)
		r.SetAdd(0)

	case objabi.R_RISCV_CALL:
		// Nothing to do, already using AUIPC+JALR.

	default:
		ctxt.Errorf(s, "trampoline called with non-jump reloc: %d (%s)", r.Type(), sym.RelocName(ctxt.Arch, r.Type()))
	}
}

func genCallTramp(arch *sys.Arch, linkmode ld.LinkMode, ldr *loader.Loader, tramp *loader.SymbolBuilder, target loader.Sym, offset int64) {
	tramp.AddUint32(arch, 0x00000f97) // AUIPC	$0, X31
	tramp.AddUint32(arch, 0x000f8067) // JALR	X0, (X31)

	r, _ := tramp.AddRel(objabi.R_RISCV_CALL)
	r.SetSiz(8)
	r.SetSym(target)
	r.SetAdd(offset)
}

"""



```