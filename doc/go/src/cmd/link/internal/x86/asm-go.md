Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Context:**

* **File Path:** `go/src/cmd/link/internal/x86/asm.go` immediately tells us this is part of the Go linker (`cmd/link`), specifically dealing with the x86 architecture. The `asm.go` name suggests it's related to assembly code generation or manipulation.
* **Copyright Header:**  Indicates a long history, originating from Inferno OS, and eventually contributed to Go. This often means the code handles low-level details.
* **Package Declaration:** `package x86` confirms the architecture-specific nature of this code.
* **Imports:**  The imported packages are crucial for understanding the code's dependencies and functions:
    * `cmd/internal/objabi`:  Likely contains definitions for object file formats and ABI details.
    * `cmd/internal/sys`: Provides system architecture information.
    * `cmd/link/internal/ld`:  Core linker functionality.
    * `cmd/link/internal/loader`:  Handles loading and managing object files and symbols.
    * `cmd/link/internal/sym`:  Represents symbols within the linking process.
    * `debug/elf`:  Provides ELF file format parsing and manipulation.
    * `log`:  For error logging.

**2. `gentext` Function Analysis:**

* **Purpose:** The name suggests it generates text (code) during the linking process.
* **Conditions:** The function's execution is conditional based on `ctxt.DynlinkingGo()` and `ctxt.BuildMode`. This immediately points to handling different linking scenarios (dynamic vs. static linking, different output formats like C archives, PIE executables, etc.).
* **Thunk Generation:** The core of the `gentext` function is the generation of "thunks."  The loop iterating over register names strongly suggests these thunks are small code snippets that load the program counter (PC) into specific registers. The assembly code (`mov (%esp),%eax`, `ret`) confirms this. The purpose is to get the current instruction's address.
* **`addmoduledata`:**  The call to `ld.PrepareAddmoduledata` and the subsequent assembly code strongly imply this function is involved in setting up the Go runtime's module data structure. The assembly instructions (`push %ebx`, `call __x86.get_pc_thunk.cx`, etc.) are typical prologue code for calling a function and setting up necessary registers. The relocations (`R_CALL`, `R_PCREL`, `R_GOTPC`) further support this.
* **Inference:** `gentext` seems to generate small pieces of assembly code needed for specific linking modes and the initialization of the Go runtime, particularly the module data.

**3. `adddynrel` Function Analysis:**

* **Purpose:** The name indicates handling dynamic relocations.
* **Relocation Types:** The `switch r.Type()` statement is the heart of this function. It handles various relocation types defined in `objabi` and related to ELF and Mach-O formats.
* **ELF Relocations (e.g., `elf.R_386_PC32`, `elf.R_386_PLT32`, `elf.R_386_GOT32`):** These cases deal with standard ELF relocation types for x86. The code modifies relocation types and adds/updates symbol references, particularly related to the Procedure Linkage Table (PLT) and Global Offset Table (GOT).
* **Mach-O Relocations:** Handles specific Mach-O relocation types.
* **Dynamic Symbol Handling (`targType == sym.SDYNIMPORT`):** A significant portion of the code deals with relocations to dynamically linked symbols. It ensures PLT entries are created and GOT entries are managed.
* **Inference:** `adddynrel` is responsible for processing relocations, especially for dynamic linking, ensuring that external symbols are resolved correctly at runtime using mechanisms like the PLT and GOT.

**4. `elfreloc1`, `machoreloc1`, `pereloc1` Functions:**

* **Purpose:**  These functions seem to generate the actual relocation entries in the output object file, specific to ELF, Mach-O, and PE (Windows) formats, respectively. The "1" suggests processing a single relocation.
* **Output:** They write data to an `ld.OutBuf`, which is used to build the output file.
* **Relocation Encoding:** They translate Go's internal relocation types (`objabi.R_ADDR`, `objabi.R_CALL`, etc.) into the specific numerical encodings required by the respective file formats (e.g., `elf.R_386_32`, `ld.IMAGE_REL_I386_REL32`).
* **Inference:** These functions handle the final encoding of relocation information into the binary output.

**5. `elfsetupplt` and `addpltsym` Functions:**

* **Purpose:**  These functions are clearly related to setting up the Procedure Linkage Table (PLT) for dynamic linking in ELF.
* **`elfsetupplt`:**  Initializes the PLT with a standard prologue that pushes the GOT address and jumps to the GOT entry.
* **`addpltsym`:** Adds an entry to the PLT for a specific dynamic symbol. This involves adding code to the PLT that jumps to the GOT entry for that symbol and creating a corresponding GOT entry.
* **Inference:** These functions implement the core mechanism for lazy binding of dynamically linked functions in ELF.

**6. General Observations and Error Handling:**

* **Error Logging:** The code uses `ldr.Errorf` extensively for reporting errors during relocation processing, especially when encountering unexpected relocation types or inconsistencies.
* **Architecture Specificity:** The code is clearly tailored for the x86 architecture.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** "Maybe `gentext` just generates some boilerplate code."
* **Refinement:** Looking at the thunk generation and the `addmoduledata` sequence, it's clear it's more specifically about runtime initialization and getting the PC.
* **Initial thought:** "`adddynrel` just modifies relocation addresses."
* **Refinement:** Recognizing the PLT/GOT logic clarifies that it's about transforming relocations to work with dynamic linking.
* **Initial thought:** The `...reloc1` functions seem similar.
* **Refinement:**  Noticing the file format-specific imports and the different relocation encodings makes it clear they are format-specific implementations.

By systematically analyzing the function names, logic, imported packages, and assembly snippets, we can build a strong understanding of the code's purpose and functionality within the Go linker for the x86 architecture.
`go/src/cmd/link/internal/x86/asm.go` 是 Go 语言链接器 (`cmd/link`) 中专门处理 x86 架构汇编相关操作的部分。它的主要功能包括：

**1. 生成用于获取程序计数器 (PC) 的 "thunk" 函数:**

* **功能:**  在某些链接模式下 (例如动态链接、生成 C 归档文件、PIE 可执行文件等)，需要一种方法来获取当前指令的地址。这段代码生成了一些小的汇编函数，每个函数都将当前 PC 值加载到特定的寄存器中。
* **实现原理:**  它循环遍历 x86 的通用寄存器 (ax, cx, dx, bx, bp, si, di)，为每个寄存器生成一个名为 `__x86.get_pc_thunk.<寄存器名>` 的函数。这些函数使用 `mov (%esp), %eax` (或其他目标寄存器) 指令将栈顶的值 (即返回地址，也接近当前 PC) 加载到寄存器中，然后使用 `ret` 指令返回。
* **Go 代码示例 (概念性):**  虽然 Go 代码本身不能直接生成这样的 thunk，但我们可以理解其作用：

```go
// 假设我们有这样一个 thunk 函数 (实际是汇编)
// func get_pc_thunk_ax() uintptr {
//   // mov (%esp), %eax
//   // ret
// }

func someFunction() uintptr {
	pc := get_pc_thunk_ax() // 调用 thunk 获取 PC
	// ... 使用 pc 值 ...
	return pc
}
```

* **假设输入与输出:**  假设程序执行到 `someFunction` 中的 `get_pc_thunk_ax()` 调用处，`get_pc_thunk_ax()` 的输出将是紧随其调用指令之后的指令的地址。

**2. 生成用于添加模块元数据的代码 (`gentext` 函数):**

* **功能:**  在程序启动时，需要将程序的模块元数据 (例如包信息、类型信息等) 添加到 Go 运行时系统中。`gentext` 函数会生成一小段汇编代码来调用 `runtime.addmoduledata` 函数，并将模块元数据的地址作为参数传递给它。
* **实现原理:**  `gentext` 函数生成一个名为 `go.link.addmoduledata` 的汇编函数。这个函数会：
    * 将 `%ebx` 寄存器压栈 (保存其值)。
    * 调用之前生成的获取 PC 的 thunk 函数 (`__x86.get_pc_thunk.cx`)，将 PC 值加载到 `%ecx` 寄存器中。
    * 使用 `lea` 指令计算模块元数据的地址，并将其加载到 `%eax`。这里使用了 `R_PCREL` 类型的重定位，表示相对于 PC 的偏移量。
    * 如果支持 GOT (Global Offset Table)，还会计算 GOT 的地址。
    * 调用 `runtime.addmoduledata` 函数，将模块元数据的地址作为参数传递。
    * 将之前压栈的 `%ebx` 寄存器弹出 (恢复其值)。
    * 使用 `ret` 指令返回。
* **Go 代码示例 (概念性):**

```go
// 假设 go.link.addmoduledata 函数最终会调用 runtime.addmoduledata

//go:linkname addmoduledata runtime.addmoduledata
func addmoduledata(md unsafe.Pointer)

func init() {
	// go.link.addmoduledata 会在这里被调用 (链接器生成)
}
```

* **假设输入与输出:**  当程序启动并执行到 `init` 函数时，链接器生成的 `go.link.addmoduledata` 代码会被执行。该代码会获取模块元数据的地址，并将其传递给 `runtime.addmoduledata` 函数，最终将模块信息注册到 Go 运行时。

**3. 处理动态链接相关的重定位 (`adddynrel` 函数):**

* **功能:**  当程序需要链接动态库时，需要处理各种类型的重定位，以确保程序能够正确地调用动态库中的函数和访问其中的数据。`adddynrel` 函数负责处理 x86 架构下的动态链接重定位。
* **实现原理:**  该函数接收一个重定位信息 (`r`)，并根据其类型 (`r.Type()`) 进行不同的处理。它会处理 ELF 和 Mach-O 格式的重定位类型，例如：
    * **`R_386_PC32`:**  计算相对于 PC 的 32 位偏移。
    * **`R_386_PLT32`:**  用于调用动态库中的函数，需要设置 PLT (Procedure Linkage Table) 表项。
    * **`R_386_GOT32`, `R_386_GOT32X`:**  用于访问动态库中的全局变量，需要使用 GOT (Global Offset Table)。
    * **`R_386_GOTOFF`:**  计算相对于 GOT 的偏移。
    * **`R_386_GOTPC`:**  计算 GOT 的地址。
    * **`R_386_32`:**  32 位绝对地址。
    * **Mach-O 相关的重定位类型:** 处理 Mach-O 格式下的动态链接。
* **代码推理与假设输入输出:**  以 `objabi.ElfRelocOffset + objabi.RelocType(elf.R_386_PLT32)` 为例：
    * **假设输入:**  一个指向需要调用的动态库函数的重定位信息 `r`，其类型为 `R_386_PLT32`。
    * **处理过程:**
        1. 调用 `addpltsym` 函数为该动态库函数在 PLT 中创建一个表项。
        2. 更新当前重定位的类型为 `objabi.R_PCREL` (相对于 PC 的偏移)。
        3. 将重定位的目标符号设置为 PLT 表的符号 (`syms.PLT`).
        4. 将重定位的加数设置为该动态库函数在 PLT 中的偏移量 (`ldr.SymPlt(targ)`).
    * **输出:**  修改后的重定位信息，以便链接器能够生成正确的 PLT 调用代码。

**4. 生成特定平台格式的重定位条目 (`elfreloc1`, `machoreloc1`, `pereloc1` 函数):**

* **功能:**  这些函数根据目标平台的格式 (ELF, Mach-O, PE) 将 Go 内部的重定位类型转换为目标平台特定的重定位条目。
* **实现原理:**  它们接收一个重定位信息，并将其转换为目标平台的重定位结构。例如，`elfreloc1` 函数会将 `objabi.R_ADDR` 转换为 `elf.R_386_32`，将 `objabi.R_CALL` 转换为 `elf.R_386_PLT32` (如果目标是动态导入的符号) 或 `elf.R_386_PC32`。

**5. 设置 PLT 表 (`elfsetupplt` 函数):**

* **功能:**  为 ELF 格式的可执行文件设置 PLT (Procedure Linkage Table)。PLT 用于延迟绑定动态链接的函数。
* **实现原理:**  `elfsetupplt` 函数会在 PLT 段中添加一些初始代码，这些代码会跳转到 GOT (Global Offset Table) 中相应的条目，以解析动态链接的函数地址。

**6. 添加 PLT 符号 (`addpltsym` 函数):**

* **功能:**  为动态链接的符号在 PLT 中添加一个条目。
* **实现原理:**  如果符号尚未在 PLT 中，`addpltsym` 函数会在 PLT 段中添加新的跳转指令，并在 GOT 中分配相应的条目。

**命令行参数的具体处理:**

该文件本身不直接处理命令行参数。链接器的命令行参数处理位于 `cmd/link/internal/ld` 包中。这个文件中的代码是在链接过程的某个阶段被 `ld` 包调用的，它接收的是已经解析过的链接上下文信息 (`ld.Link`)。

**使用者易犯错的点:**

对于直接使用这个包的开发者来说，不太容易犯错，因为这是链接器内部的实现细节，不是给普通 Go 开发者直接使用的 API。

**总结:**

`go/src/cmd/link/internal/x86/asm.go` 是 Go 链接器中负责 x86 架构汇编代码生成和重定位处理的关键部分。它生成用于获取 PC 的 thunk 函数，生成用于初始化模块元数据的代码，并处理动态链接相关的各种重定位类型，最终生成特定平台格式的重定位条目，确保程序能够正确地链接和执行。

### 提示词
```
这是路径为go/src/cmd/link/internal/x86/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Inferno utils/8l/asm.c
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/8l/asm.c
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

package x86

import (
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/ld"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/elf"
	"log"
)

func gentext(ctxt *ld.Link, ldr *loader.Loader) {
	if ctxt.DynlinkingGo() {
		// We need get_pc_thunk.
	} else {
		switch ctxt.BuildMode {
		case ld.BuildModeCArchive:
			if !ctxt.IsELF {
				return
			}
		case ld.BuildModePIE, ld.BuildModeCShared, ld.BuildModePlugin:
			// We need get_pc_thunk.
		default:
			return
		}
	}

	// Generate little thunks that load the PC of the next instruction into a register.
	thunks := make([]loader.Sym, 0, 7+len(ctxt.Textp))
	for _, r := range [...]struct {
		name string
		num  uint8
	}{
		{"ax", 0},
		{"cx", 1},
		{"dx", 2},
		{"bx", 3},
		// sp
		{"bp", 5},
		{"si", 6},
		{"di", 7},
	} {
		thunkfunc := ldr.CreateSymForUpdate("__x86.get_pc_thunk."+r.name, 0)
		thunkfunc.SetType(sym.STEXT)
		ldr.SetAttrLocal(thunkfunc.Sym(), true)
		o := func(op ...uint8) {
			for _, op1 := range op {
				thunkfunc.AddUint8(op1)
			}
		}
		// 8b 04 24	mov    (%esp),%eax
		// Destination register is in bits 3-5 of the middle byte, so add that in.
		o(0x8b, 0x04+r.num<<3, 0x24)
		// c3		ret
		o(0xc3)

		thunks = append(thunks, thunkfunc.Sym())
	}
	ctxt.Textp = append(thunks, ctxt.Textp...) // keep Textp in dependency order

	initfunc, addmoduledata := ld.PrepareAddmoduledata(ctxt)
	if initfunc == nil {
		return
	}

	o := func(op ...uint8) {
		for _, op1 := range op {
			initfunc.AddUint8(op1)
		}
	}

	// go.link.addmoduledata:
	//      53                      push %ebx
	//      e8 00 00 00 00          call __x86.get_pc_thunk.cx + R_CALL __x86.get_pc_thunk.cx
	//      8d 81 00 00 00 00       lea 0x0(%ecx), %eax + R_PCREL ctxt.Moduledata
	//      8d 99 00 00 00 00       lea 0x0(%ecx), %ebx + R_GOTPC _GLOBAL_OFFSET_TABLE_
	//      e8 00 00 00 00          call runtime.addmoduledata@plt + R_CALL runtime.addmoduledata
	//      5b                      pop %ebx
	//      c3                      ret

	o(0x53)

	o(0xe8)
	initfunc.AddSymRef(ctxt.Arch, ldr.Lookup("__x86.get_pc_thunk.cx", 0), 0, objabi.R_CALL, 4)

	o(0x8d, 0x81)
	initfunc.AddPCRelPlus(ctxt.Arch, ctxt.Moduledata, 6)

	o(0x8d, 0x99)
	gotsym := ldr.LookupOrCreateSym("_GLOBAL_OFFSET_TABLE_", 0)
	initfunc.AddSymRef(ctxt.Arch, gotsym, 12, objabi.R_PCREL, 4)
	o(0xe8)
	initfunc.AddSymRef(ctxt.Arch, addmoduledata, 0, objabi.R_CALL, 4)

	o(0x5b)

	o(0xc3)
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
	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_386_PC32):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_386_PC32 relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		if targType == 0 || targType == sym.SXREF {
			ldr.Errorf(s, "unknown symbol %s in pcrel", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocAdd(rIdx, r.Add()+4)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_386_PLT32):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocAdd(rIdx, r.Add()+4)
		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			su.SetRelocSym(rIdx, syms.PLT)
			su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymPlt(targ)))
		}

		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_386_GOT32),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_386_GOT32X):
		su := ldr.MakeSymbolUpdater(s)
		if targType != sym.SDYNIMPORT {
			// have symbol
			sData := ldr.Data(s)

			if r.Off() >= 2 && sData[r.Off()-2] == 0x8b {
				su.MakeWritable()

				// turn MOVL of GOT entry into LEAL of symbol address, relative to GOT.
				writeableData := su.Data()
				writeableData[r.Off()-2] = 0x8d
				su.SetRelocType(rIdx, objabi.R_GOTOFF)
				return true
			}

			if r.Off() >= 2 && sData[r.Off()-2] == 0xff && sData[r.Off()-1] == 0xb3 {
				su.MakeWritable()
				// turn PUSHL of GOT entry into PUSHL of symbol itself.
				// use unnecessary SS prefix to keep instruction same length.
				writeableData := su.Data()
				writeableData[r.Off()-2] = 0x36
				writeableData[r.Off()-1] = 0x68
				su.SetRelocType(rIdx, objabi.R_ADDR)
				return true
			}

			ldr.Errorf(s, "unexpected GOT reloc for non-dynamic symbol %s", ldr.SymName(targ))
			return false
		}

		ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_386_GLOB_DAT))
		su.SetRelocType(rIdx, objabi.R_CONST) // write r->add during relocsym
		su.SetRelocSym(rIdx, 0)
		su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymGot(targ)))
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_386_GOTOFF):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_GOTOFF)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_386_GOTPC):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocSym(rIdx, syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+4)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_386_32):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_386_32 relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ADDR)
		return true

	case objabi.MachoRelocOffset + ld.MACHO_GENERIC_RELOC_VANILLA*2 + 0:
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ADDR)
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected reloc for dynamic symbol %s", ldr.SymName(targ))
		}
		return true

	case objabi.MachoRelocOffset + ld.MACHO_GENERIC_RELOC_VANILLA*2 + 1:
		su := ldr.MakeSymbolUpdater(s)
		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			su.SetRelocSym(rIdx, syms.PLT)
			su.SetRelocAdd(rIdx, int64(ldr.SymPlt(targ)))
			su.SetRelocType(rIdx, objabi.R_PCREL)
			return true
		}

		su.SetRelocType(rIdx, objabi.R_PCREL)
		return true

	case objabi.MachoRelocOffset + ld.MACHO_FAKE_GOTPCREL:
		su := ldr.MakeSymbolUpdater(s)
		if targType != sym.SDYNIMPORT {
			// have symbol
			// turn MOVL of GOT entry into LEAL of symbol itself
			sData := ldr.Data(s)
			if r.Off() < 2 || sData[r.Off()-2] != 0x8b {
				ldr.Errorf(s, "unexpected GOT reloc for non-dynamic symbol %s", ldr.SymName(targ))
				return false
			}

			su.MakeWritable()
			writeableData := su.Data()
			writeableData[r.Off()-2] = 0x8d
			su.SetRelocType(rIdx, objabi.R_PCREL)
			return true
		}

		ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_386_GLOB_DAT))
		su.SetRelocSym(rIdx, syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymGot(targ)))
		su.SetRelocType(rIdx, objabi.R_PCREL)
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
	case objabi.R_CALL,
		objabi.R_PCREL:
		if target.IsExternal() {
			// External linker will do this relocation.
			return true
		}
		addpltsym(target, ldr, syms, targ)
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocSym(rIdx, syms.PLT)
		su.SetRelocAdd(rIdx, int64(ldr.SymPlt(targ)))
		return true

	case objabi.R_ADDR:
		if !ldr.SymType(s).IsDATA() {
			break
		}
		if target.IsElf() {
			ld.Adddynsym(ldr, target, syms, targ)
			rel := ldr.MakeSymbolUpdater(syms.Rel)
			rel.AddAddrPlus(target.Arch, s, int64(r.Off()))
			rel.AddUint32(target.Arch, elf.R_INFO32(uint32(ldr.SymDynid(targ)), uint32(elf.R_386_32)))
			su := ldr.MakeSymbolUpdater(s)
			su.SetRelocType(rIdx, objabi.R_CONST) // write r->add during relocsym
			su.SetRelocSym(rIdx, 0)
			return true
		}
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
			out.Write32(uint32(elf.R_386_32) | uint32(elfsym)<<8)
		} else {
			return false
		}
	case objabi.R_GOTPCREL:
		if siz == 4 {
			out.Write32(uint32(elf.R_386_GOTPC))
			if ldr.SymName(r.Xsym) != "_GLOBAL_OFFSET_TABLE_" {
				out.Write32(uint32(sectoff))
				out.Write32(uint32(elf.R_386_GOT32) | uint32(elfsym)<<8)
			}
		} else {
			return false
		}
	case objabi.R_CALL:
		if siz == 4 {
			if ldr.SymType(r.Xsym) == sym.SDYNIMPORT {
				out.Write32(uint32(elf.R_386_PLT32) | uint32(elfsym)<<8)
			} else {
				out.Write32(uint32(elf.R_386_PC32) | uint32(elfsym)<<8)
			}
		} else {
			return false
		}
	case objabi.R_PCREL:
		if siz == 4 {
			out.Write32(uint32(elf.R_386_PC32) | uint32(elfsym)<<8)
		} else {
			return false
		}
	case objabi.R_TLS_LE:
		if siz == 4 {
			out.Write32(uint32(elf.R_386_TLS_LE) | uint32(elfsym)<<8)
		} else {
			return false
		}
	case objabi.R_TLS_IE:
		if siz == 4 {
			out.Write32(uint32(elf.R_386_GOTPC))
			out.Write32(uint32(sectoff))
			out.Write32(uint32(elf.R_386_TLS_GOTIE) | uint32(elfsym)<<8)
		} else {
			return false
		}
	}

	return true
}

func machoreloc1(*sys.Arch, *ld.OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool {
	return false
}

func pereloc1(arch *sys.Arch, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, sectoff int64) bool {
	var v uint32

	rs := r.Xsym
	rt := r.Type

	if ldr.SymDynid(rs) < 0 {
		ldr.Errorf(s, "reloc %d (%s) to non-coff symbol %s type=%d (%s)", rt, sym.RelocName(arch, rt), ldr.SymName(rs), ldr.SymType(rs), ldr.SymType(rs))
		return false
	}

	out.Write32(uint32(sectoff))
	out.Write32(uint32(ldr.SymDynid(rs)))

	switch rt {
	default:
		return false

	case objabi.R_DWARFSECREF:
		v = ld.IMAGE_REL_I386_SECREL

	case objabi.R_ADDR:
		v = ld.IMAGE_REL_I386_DIR32

	case objabi.R_PEIMAGEOFF:
		v = ld.IMAGE_REL_I386_DIR32NB

	case objabi.R_CALL,
		objabi.R_PCREL:
		v = ld.IMAGE_REL_I386_REL32
	}

	out.Write16(uint16(v))

	return true
}

func archreloc(*ld.Target, *loader.Loader, *ld.ArchSyms, loader.Reloc, loader.Sym, int64) (int64, int, bool) {
	return -1, 0, false
}

func archrelocvariant(*ld.Target, *loader.Loader, loader.Reloc, sym.RelocVariant, loader.Sym, int64, []byte) int64 {
	log.Fatalf("unexpected relocation variant")
	return -1
}

func elfsetupplt(ctxt *ld.Link, ldr *loader.Loader, plt, got *loader.SymbolBuilder, dynamic loader.Sym) {
	if plt.Size() == 0 {
		// pushl got+4
		plt.AddUint8(0xff)

		plt.AddUint8(0x35)
		plt.AddAddrPlus(ctxt.Arch, got.Sym(), 4)

		// jmp *got+8
		plt.AddUint8(0xff)

		plt.AddUint8(0x25)
		plt.AddAddrPlus(ctxt.Arch, got.Sym(), 8)

		// zero pad
		plt.AddUint32(ctxt.Arch, 0)

		// assume got->size == 0 too
		got.AddAddrPlus(ctxt.Arch, dynamic, 0)

		got.AddUint32(ctxt.Arch, 0)
		got.AddUint32(ctxt.Arch, 0)
	}
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

		// jmpq *got+size
		plt.AddUint8(0xff)

		plt.AddUint8(0x25)
		plt.AddAddrPlus(target.Arch, got.Sym(), got.Size())

		// add to got: pointer to current pos in plt
		got.AddAddrPlus(target.Arch, plt.Sym(), plt.Size())

		// pushl $x
		plt.AddUint8(0x68)

		plt.AddUint32(target.Arch, uint32(rel.Size()))

		// jmp .plt
		plt.AddUint8(0xe9)

		plt.AddUint32(target.Arch, uint32(-(plt.Size() + 4)))

		// rel
		rel.AddAddrPlus(target.Arch, got.Sym(), got.Size()-4)

		sDynid := ldr.SymDynid(s)
		rel.AddUint32(target.Arch, elf.R_INFO32(uint32(sDynid), uint32(elf.R_386_JMP_SLOT)))

		ldr.SetPlt(s, int32(plt.Size()-16))
	} else {
		ldr.Errorf(s, "addpltsym: unsupported binary format")
	}
}
```