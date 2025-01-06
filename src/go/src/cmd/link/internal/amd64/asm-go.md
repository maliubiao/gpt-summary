Response:
Let's break down the thought process for analyzing this `asm.go` file.

1. **Understand the Context:** The file path `go/src/cmd/link/internal/amd64/asm.go` immediately tells us this is part of the Go linker (`cmd/link`). Specifically, it's within the `amd64` architecture directory and the `internal` package, suggesting architecture-specific assembly and linking logic that's not intended for public consumption. The name `asm.go` strongly hints at handling assembly-level details, likely related to instruction generation and relocation. The copyright header confirms its origin within the Go project and its history.

2. **Identify Key Functions:**  A quick scan reveals several top-level functions: `PADDR`, `gentext`, `adddynrel`, `elfreloc1`, `machoreloc1`, `pereloc1`, `archreloc`, `archrelocvariant`, `elfsetupplt`, `addpltsym`, and `tlsIEtoLE`. These function names provide clues about their roles.

3. **Analyze Individual Functions (First Pass - High Level):**

    * `PADDR`: Looks like a simple bit manipulation function. The name suggests it's related to physical addresses.
    * `gentext`: "Generate text" suggests generating code. The references to `addmoduledata` are a strong hint it's related to the Go runtime initialization.
    * `adddynrel`: "Add dynamic relocation."  This clearly deals with adding dynamic relocation entries, crucial for shared libraries and position-independent executables.
    * `elfreloc1`, `machoreloc1`, `pereloc1`:  The suffixes "elf", "macho", and "pe" strongly suggest these functions handle relocation for specific executable formats (ELF, Mach-O, and PE respectively). The "1" might indicate they handle individual relocation entries.
    * `archreloc`, `archrelocvariant`: "Architecture relocation."  Likely the main entry point for handling relocations, with `archrelocvariant` possibly handling less common or variant relocation types.
    * `elfsetupplt`: "ELF setup PLT." This likely sets up the Procedure Linkage Table (PLT), a key component for dynamic linking in ELF.
    * `addpltsym`: "Add PLT symbol."  This probably adds an entry to the PLT for a given symbol.
    * `tlsIEtoLE`: "TLS IE to LE."  TLS stands for Thread-Local Storage. "IE" and "LE" likely refer to different addressing models (Indirectly Encoded and Locally Encoded). This function seems to convert between them.

4. **Analyze Functions (Second Pass - Deeper Dive & Code Inspection):**

    * **`gentext`:**  The assembly code snippet within the function is very telling. It's setting up a call to `runtime.addmoduledata`. The comments clearly label the assembly instructions and their corresponding relocations. This confirms its role in runtime initialization.

    * **`adddynrel`:** This function is a large switch statement based on relocation types. It handles various ELF and Mach-O relocation types (`R_X86_64_PC32`, `R_X86_64_PLT32`, etc.). The logic involves creating GOT (Global Offset Table) and PLT entries and modifying existing relocations. The `target.IsPIE()` checks indicate handling for Position Independent Executables.

    * **`elfreloc1`, `machoreloc1`, `pereloc1`:** These functions translate Go's internal relocation types (`objabi.R_ADDR`, `objabi.R_CALL`, etc.) into the specific relocation encodings for ELF, Mach-O, and PE, respectively. They write the relocation information to the output buffer.

    * **`elfsetupplt`:**  The assembly code here sets up the initial PLT entries. It pushes the GOT address onto the stack and jumps to a GOT entry. This is the standard PLT setup for lazy binding.

    * **`addpltsym`:** This function adds a new entry to the PLT. The logic differs slightly between ELF and Mach-O, demonstrating the platform-specific handling. It also calls `ld.Adddynsym`, indicating the addition of symbols to the dynamic symbol table.

    * **`tlsIEtoLE`:** The code comments and the op-code manipulation reveal its purpose: transforming a PC-relative access to thread-local storage into a direct load of the TLS address.

5. **Identify Key Concepts and Functionality:** Based on the function analysis, the core functionalities are:

    * **Generating Initialization Code:** `gentext` for setting up the `runtime.addmoduledata` call.
    * **Handling Relocations:**  `adddynrel`, `elfreloc1`, `machoreloc1`, `pereloc1`, `archreloc`, `archrelocvariant` for adjusting addresses in the compiled code to account for different memory layouts at runtime.
    * **Dynamic Linking Support:** `elfsetupplt` and `addpltsym` for creating and managing the PLT and GOT, essential for resolving external symbols at runtime.
    * **TLS Handling:** `tlsIEtoLE` for converting TLS addressing modes.

6. **Infer Go Language Features:**

    * **`//go:linkname` (Implied):** While not explicitly present in this snippet, the interaction with `runtime.addmoduledata` strongly suggests that other parts of the linker use `//go:linkname` to connect symbols in the `cmd/link` package to corresponding symbols in the `runtime` package. This is a key mechanism for the linker to interact with the Go runtime.
    * **Dynamic Linking:** The extensive handling of PLT and GOT directly relates to Go's support for creating shared libraries and plugins.
    * **Position Independent Executables (PIE):** The `target.IsPIE()` checks highlight Go's ability to create executables that can be loaded at any address in memory.
    * **Thread-Local Storage (TLS):** The `tlsIEtoLE` function demonstrates support for thread-specific data.

7. **Construct Examples and Scenarios:** Based on the inferred features, create illustrative examples.

    * **Dynamic Linking Example:** A simple program that imports an external package.
    * **PIE Example:**  Explain how to build a PIE executable and how relocations make it work.
    * **TLS Example:** A program using `go:linkname` and the `runtime` package to access thread-local storage. (While `tlsIEtoLE` is internal, demonstrating a basic TLS usage helps).

8. **Identify Potential Pitfalls:** Think about common mistakes developers might make when interacting with linking or dynamic linking concepts.

    * **Incorrect Import Paths:** A classic Go error.
    * **Shared Library Issues (Versioning, Dependencies):**  General dynamic linking problems.
    * **Misunderstanding `go:linkname`:**  Using it incorrectly can lead to undefined behavior.

9. **Refine and Organize:**  Structure the analysis logically, starting with basic functionality and moving towards more complex concepts. Use clear language and code examples. Ensure the explanation aligns with the provided code snippet.

This iterative process of understanding the context, identifying key elements, analyzing code details, inferring high-level functionality, and constructing examples leads to a comprehensive understanding of the `asm.go` file's role in the Go linker.
`go/src/cmd/link/internal/amd64/asm.go` 文件是 Go 语言链接器（`cmd/link`）中专门针对 `amd64` 架构的代码生成和重定位部分。它负责将编译后的目标文件链接成最终的可执行文件或共享库。

以下是该文件的一些主要功能：

1. **生成启动代码 (`gentext` 函数):**
   - 该函数负责生成程序启动时需要执行的一小段代码。
   - 具体来说，它生成了调用 `runtime.addmoduledata` 函数的代码。
   - `runtime.addmoduledata` 用于向 Go 运行时注册模块元数据，这对于 Go 程序的正常启动和管理至关重要，例如垃圾回收、反射等。

   **Go 代码示例（模拟 `runtime.addmoduledata` 的调用场景）:**

   ```go
   package main

   import (
       "fmt"
       "unsafe"
   )

   // 假设的 _moduleData 结构体 (与实际运行时结构类似)
   type _moduleData struct {
       pclntable []byte
       ftab      []byte
       filetab   []byte
       // ... 其他字段
   }

   // 模拟 runtime.addmoduledata 的行为
   func addmoduledata(md *(_moduleData)) {
       fmt.Println("添加模块元数据:", md)
       // 在实际运行时中，会将 md 添加到全局链表中
   }

   var firstmoduledata _moduleData // 模拟 runtime.firstmoduledata

   func main() {
       // 在链接过程中，`gentext` 会生成类似下面的汇编代码，
       // 用于在程序启动时调用 `addmoduledata(&firstmoduledata)`

       // 以下代码仅为模拟，实际由链接器生成
       mdPtr := unsafe.Pointer(&firstmoduledata)
       addmoduledata((*_moduleData)(mdPtr))
   }
   ```

   **假设的输入与输出:**

   - **输入:** 链接器接收到编译后的目标文件，其中包含了 `main` 包的符号信息和代码。
   - **输出:**  `gentext` 函数会生成一段汇编代码，这段代码在程序启动时执行，会将指向 `firstmoduledata` 的指针作为参数传递给 `runtime.addmoduledata` (或我们模拟的 `addmoduledata`)。

2. **处理动态重定位 (`adddynrel` 函数):**
   - 该函数处理与动态链接相关的重定位。
   - 当链接生成共享库或位置无关可执行文件 (PIE) 时，某些符号的地址在链接时无法确定，需要在运行时进行重定位。
   - `adddynrel` 函数根据不同的重定位类型（例如 `R_X86_64_PC32`, `R_X86_64_PLT32`, `R_X86_64_GOTPCREL` 等，这些是 ELF 格式的重定位类型）来生成相应的动态重定位条目。
   - 它还处理了 Mach-O 和 PE 格式的重定位。
   - 该函数还负责创建和管理 PLT (Procedure Linkage Table) 和 GOT (Global Offset Table)，这对于动态链接至关重要。

   **Go 代码示例（演示动态链接的概念）:**

   ```go
   // 假设我们有一个外部共享库 external.so，其中定义了一个函数 externalFunc

   package main

   import "fmt"

   //go:linkname externalFunc externalFunc // 假设 externalFunc 在外部共享库中

   func externalFunc() // 声明外部函数

   func main() {
       fmt.Println("准备调用外部函数...")
       externalFunc() // 调用外部函数，需要动态链接器在运行时解析其地址
       fmt.Println("外部函数调用完成。")
   }
   ```

   **涉及代码推理与假设的输入与输出:**

   - **假设的输入:**  链接器正在链接一个需要调用外部共享库中 `externalFunc` 函数的程序。目标平台是 Linux，使用 ELF 格式。
   - **代码推理:**  `adddynrel` 函数会检测到对 `externalFunc` 的引用，并生成一个类似于 `R_X86_64_PLT32` 的重定位条目。同时，会生成 PLT 和 GOT 的相关条目。
   - **输出:** 最终生成的可执行文件中，对于 `externalFunc` 的调用，不会直接写入其绝对地址，而是会生成一条跳转到 PLT 中对应条目的指令。PLT 条目会通过 GOT 来间接调用 `externalFunc`。动态链接器在程序加载时会解析 `externalFunc` 的实际地址，并填充到 GOT 中。

3. **处理 ELF、Mach-O 和 PE 格式的重定位 (`elfreloc1`, `machoreloc1`, `pereloc1` 函数):**
   - 这些函数分别负责将 Go 内部的重定位类型转换为特定操作系统和可执行文件格式（ELF, Mach-O, PE）的重定位条目。
   - 它们将重定位信息写入到输出文件的相应节区中。

4. **设置 PLT (`elfsetupplt` 函数):**
   - 对于 ELF 格式的可执行文件，该函数负责设置 PLT 的初始结构。
   - PLT 是一小段代码，用于延迟绑定动态链接的函数。

5. **添加 PLT 符号 (`addpltsym` 函数):**
   - 当程序需要调用动态链接的外部函数时，该函数会在 PLT 中添加相应的条目。

6. **TLS IE 到 LE 的转换 (`tlsIEtoLE` 函数):**
   - 该函数用于将线程局部存储 (TLS) 的间接编码 (IE) 转换为局部编码 (LE)。
   - 这通常涉及到修改指令的操作码，以便更高效地访问 TLS 数据。

**命令行参数的具体处理:**

该文件本身并不直接处理命令行参数。命令行参数的处理主要发生在 `cmd/link/internal/ld` 包中的其他文件中，例如 `ld.go`。`asm.go` 文件中的函数是由链接器的核心逻辑调用的，在调用时已经确定了链接的各种配置，包括是否生成动态链接文件、目标操作系统和架构等。

**使用者易犯错的点:**

由于 `go/src/cmd/link/internal/amd64/asm.go` 是 Go 链接器的内部实现，普通 Go 开发者不会直接与之交互。因此，不存在使用者直接犯错的场景。

然而，理解其背后的原理对于理解 Go 的链接过程和一些高级特性（如动态链接、位置无关代码）是非常有帮助的。一些与链接相关的常见错误，虽然不是直接由这个文件引起，但与其功能相关，例如：

- **动态链接问题:**  如果外部共享库未正确安装或路径配置不正确，会导致程序运行时找不到所需的符号。
- **`//go:linkname` 的滥用:**  不正确地使用 `//go:linkname` 可能会导致链接错误或运行时崩溃，因为它绕过了 Go 的类型安全检查。

**总结:**

`go/src/cmd/link/internal/amd64/asm.go` 是 Go 链接器中一个关键的架构特定文件，负责生成启动代码、处理各种类型的重定位（包括动态重定位）、设置 PLT，以及进行 TLS 相关的转换。它的功能是确保链接器能够正确地将编译后的代码链接成可执行文件或共享库，并处理与动态链接和操作系统特定的细节。 普通 Go 开发者不需要直接操作这个文件，但理解其功能有助于深入了解 Go 的底层机制。

Prompt: 
```
这是路径为go/src/cmd/link/internal/amd64/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Inferno utils/6l/asm.c
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/6l/asm.c
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

package amd64

import (
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/ld"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/elf"
	"log"
)

func PADDR(x uint32) uint32 {
	return x &^ 0x80000000
}

func gentext(ctxt *ld.Link, ldr *loader.Loader) {
	initfunc, addmoduledata := ld.PrepareAddmoduledata(ctxt)
	if initfunc == nil {
		return
	}

	o := func(op ...uint8) {
		for _, op1 := range op {
			initfunc.AddUint8(op1)
		}
	}

	// 0000000000000000 <local.dso_init>:
	//    0:	48 8d 3d 00 00 00 00 	lea    0x0(%rip),%rdi        # 7 <local.dso_init+0x7>
	// 			3: R_X86_64_PC32	runtime.firstmoduledata-0x4
	o(0x48, 0x8d, 0x3d)
	initfunc.AddPCRelPlus(ctxt.Arch, ctxt.Moduledata, 0)
	//    7:	e8 00 00 00 00       	callq  c <local.dso_init+0xc>
	// 			8: R_X86_64_PLT32	runtime.addmoduledata-0x4
	o(0xe8)
	initfunc.AddSymRef(ctxt.Arch, addmoduledata, 0, objabi.R_CALL, 4)
	//    c:	c3                   	retq
	o(0xc3)
}

func adddynrel(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym, r loader.Reloc, rIdx int) bool {
	targ := r.Sym()
	var targType sym.SymKind
	if targ != 0 {
		targType = ldr.SymType(targ)
	}

	switch rt := r.Type(); rt {
	default:
		if rt >= objabi.ElfRelocOffset {
			ldr.Errorf(s, "unexpected relocation type %d (%s)", r.Type(), sym.RelocName(target.Arch, r.Type()))
			return false
		}

		// Handle relocations found in ELF object files.
	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_X86_64_PC32):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_X86_64_PC32 relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		if targType == 0 || targType == sym.SXREF {
			ldr.Errorf(s, "unknown symbol %s in pcrel", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocAdd(rIdx, r.Add()+4)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_X86_64_PC64):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_X86_64_PC64 relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		if targType == 0 || targType == sym.SXREF {
			ldr.Errorf(s, "unknown symbol %s in pcrel", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocAdd(rIdx, r.Add()+8)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_X86_64_PLT32):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocAdd(rIdx, r.Add()+4)
		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			su.SetRelocSym(rIdx, syms.PLT)
			su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymPlt(targ)))
		}

		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_X86_64_GOTPCREL),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_X86_64_GOTPCRELX),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_X86_64_REX_GOTPCRELX):
		su := ldr.MakeSymbolUpdater(s)
		if targType != sym.SDYNIMPORT {
			// have symbol
			sData := ldr.Data(s)
			if r.Off() >= 2 && sData[r.Off()-2] == 0x8b {
				su.MakeWritable()
				// turn MOVQ of GOT entry into LEAQ of symbol itself
				writeableData := su.Data()
				writeableData[r.Off()-2] = 0x8d
				su.SetRelocType(rIdx, objabi.R_PCREL)
				su.SetRelocAdd(rIdx, r.Add()+4)
				return true
			}
		}

		// fall back to using GOT and hope for the best (CMOV*)
		// TODO: just needs relocation, no need to put in .dynsym
		ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_X86_64_GLOB_DAT))

		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocSym(rIdx, syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+4+int64(ldr.SymGot(targ)))
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_X86_64_64):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_X86_64_64 relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ADDR)
		if target.IsPIE() && target.IsInternal() {
			// For internal linking PIE, this R_ADDR relocation cannot
			// be resolved statically. We need to generate a dynamic
			// relocation. Let the code below handle it.
			break
		}
		return true

	// Handle relocations found in Mach-O object files.
	case objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_UNSIGNED*2 + 0,
		objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_SIGNED*2 + 0,
		objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_BRANCH*2 + 0:
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ADDR)

		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected reloc for dynamic symbol %s", ldr.SymName(targ))
		}
		if target.IsPIE() && target.IsInternal() {
			// For internal linking PIE, this R_ADDR relocation cannot
			// be resolved statically. We need to generate a dynamic
			// relocation. Let the code below handle it.
			if rt == objabi.MachoRelocOffset+ld.MACHO_X86_64_RELOC_UNSIGNED*2 {
				break
			} else {
				// MACHO_X86_64_RELOC_SIGNED or MACHO_X86_64_RELOC_BRANCH
				// Can this happen? The object is expected to be PIC.
				ldr.Errorf(s, "unsupported relocation for PIE: %v", rt)
			}
		}
		return true

	case objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_BRANCH*2 + 1:
		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			su := ldr.MakeSymbolUpdater(s)
			su.SetRelocSym(rIdx, syms.PLT)
			su.SetRelocType(rIdx, objabi.R_PCREL)
			su.SetRelocAdd(rIdx, int64(ldr.SymPlt(targ)))
			return true
		}
		fallthrough

	case objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_UNSIGNED*2 + 1,
		objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_SIGNED*2 + 1,
		objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_SIGNED_1*2 + 1,
		objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_SIGNED_2*2 + 1,
		objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_SIGNED_4*2 + 1:
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)

		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected pc-relative reloc for dynamic symbol %s", ldr.SymName(targ))
		}
		return true

	case objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_GOT_LOAD*2 + 1:
		if targType != sym.SDYNIMPORT {
			// have symbol
			// turn MOVQ of GOT entry into LEAQ of symbol itself
			sdata := ldr.Data(s)
			if r.Off() < 2 || sdata[r.Off()-2] != 0x8b {
				ldr.Errorf(s, "unexpected GOT_LOAD reloc for non-dynamic symbol %s", ldr.SymName(targ))
				return false
			}

			su := ldr.MakeSymbolUpdater(s)
			su.MakeWritable()
			sdata = su.Data()
			sdata[r.Off()-2] = 0x8d
			su.SetRelocType(rIdx, objabi.R_PCREL)
			return true
		}
		fallthrough

	case objabi.MachoRelocOffset + ld.MACHO_X86_64_RELOC_GOT*2 + 1:
		if targType != sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected GOT reloc for non-dynamic symbol %s", ldr.SymName(targ))
		}
		ld.AddGotSym(target, ldr, syms, targ, 0)
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocSym(rIdx, syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymGot(targ)))
		return true
	}

	// Reread the reloc to incorporate any changes in type above.
	relocs := ldr.Relocs(s)
	r = relocs.At(rIdx)

	switch r.Type() {
	case objabi.R_CALL:
		if targType != sym.SDYNIMPORT {
			// nothing to do, the relocation will be laid out in reloc
			return true
		}
		if target.IsExternal() {
			// External linker will do this relocation.
			return true
		}
		// Internal linking, for both ELF and Mach-O.
		// Build a PLT entry and change the relocation target to that entry.
		addpltsym(target, ldr, syms, targ)
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocSym(rIdx, syms.PLT)
		su.SetRelocAdd(rIdx, int64(ldr.SymPlt(targ)))
		return true

	case objabi.R_PCREL:
		if targType == sym.SDYNIMPORT && ldr.SymType(s).IsText() && target.IsDarwin() {
			// Loading the address of a dynamic symbol. Rewrite to use GOT.
			// turn LEAQ symbol address to MOVQ of GOT entry
			if r.Add() != 0 {
				ldr.Errorf(s, "unexpected nonzero addend for dynamic symbol %s", ldr.SymName(targ))
				return false
			}
			su := ldr.MakeSymbolUpdater(s)
			if r.Off() >= 2 && su.Data()[r.Off()-2] == 0x8d {
				su.MakeWritable()
				su.Data()[r.Off()-2] = 0x8b
				if target.IsInternal() {
					ld.AddGotSym(target, ldr, syms, targ, 0)
					su.SetRelocSym(rIdx, syms.GOT)
					su.SetRelocAdd(rIdx, int64(ldr.SymGot(targ)))
				} else {
					su.SetRelocType(rIdx, objabi.R_GOTPCREL)
				}
				return true
			}
			ldr.Errorf(s, "unexpected R_PCREL reloc for dynamic symbol %s: not preceded by LEAQ instruction", ldr.SymName(targ))
		}

	case objabi.R_ADDR:
		if ldr.SymType(s).IsText() && target.IsElf() {
			su := ldr.MakeSymbolUpdater(s)
			if target.IsSolaris() {
				addpltsym(target, ldr, syms, targ)
				su.SetRelocSym(rIdx, syms.PLT)
				su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymPlt(targ)))
				return true
			}
			// The code is asking for the address of an external
			// function. We provide it with the address of the
			// correspondent GOT symbol.
			ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_X86_64_GLOB_DAT))

			su.SetRelocSym(rIdx, syms.GOT)
			su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymGot(targ)))
			return true
		}

		// Process dynamic relocations for the data sections.
		if target.IsPIE() && target.IsInternal() {
			// When internally linking, generate dynamic relocations
			// for all typical R_ADDR relocations. The exception
			// are those R_ADDR that are created as part of generating
			// the dynamic relocations and must be resolved statically.
			//
			// There are three phases relevant to understanding this:
			//
			//	dodata()  // we are here
			//	address() // symbol address assignment
			//	reloc()   // resolution of static R_ADDR relocs
			//
			// At this point symbol addresses have not been
			// assigned yet (as the final size of the .rela section
			// will affect the addresses), and so we cannot write
			// the Elf64_Rela.r_offset now. Instead we delay it
			// until after the 'address' phase of the linker is
			// complete. We do this via Addaddrplus, which creates
			// a new R_ADDR relocation which will be resolved in
			// the 'reloc' phase.
			//
			// These synthetic static R_ADDR relocs must be skipped
			// now, or else we will be caught in an infinite loop
			// of generating synthetic relocs for our synthetic
			// relocs.
			//
			// Furthermore, the rela sections contain dynamic
			// relocations with R_ADDR relocations on
			// Elf64_Rela.r_offset. This field should contain the
			// symbol offset as determined by reloc(), not the
			// final dynamically linked address as a dynamic
			// relocation would provide.
			switch ldr.SymName(s) {
			case ".dynsym", ".rela", ".rela.plt", ".got.plt", ".dynamic":
				return false
			}
		} else {
			// Either internally linking a static executable,
			// in which case we can resolve these relocations
			// statically in the 'reloc' phase, or externally
			// linking, in which case the relocation will be
			// prepared in the 'reloc' phase and passed to the
			// external linker in the 'asmb' phase.
			if t := ldr.SymType(s); !t.IsDATA() && !t.IsRODATA() {
				break
			}
		}

		if target.IsElf() {
			// Generate R_X86_64_RELATIVE relocations for best
			// efficiency in the dynamic linker.
			//
			// As noted above, symbol addresses have not been
			// assigned yet, so we can't generate the final reloc
			// entry yet. We ultimately want:
			//
			// r_offset = s + r.Off
			// r_info = R_X86_64_RELATIVE
			// r_addend = targ + r.Add
			//
			// The dynamic linker will set *offset = base address +
			// addend.
			//
			// AddAddrPlus is used for r_offset and r_addend to
			// generate new R_ADDR relocations that will update
			// these fields in the 'reloc' phase.
			rela := ldr.MakeSymbolUpdater(syms.Rela)
			rela.AddAddrPlus(target.Arch, s, int64(r.Off()))
			if r.Siz() == 8 {
				rela.AddUint64(target.Arch, elf.R_INFO(0, uint32(elf.R_X86_64_RELATIVE)))
			} else {
				ldr.Errorf(s, "unexpected relocation for dynamic symbol %s", ldr.SymName(targ))
			}
			rela.AddAddrPlus(target.Arch, targ, int64(r.Add()))
			// Not mark r done here. So we still apply it statically,
			// so in the file content we'll also have the right offset
			// to the relocation target. So it can be examined statically
			// (e.g. go version).
			return true
		}

		if target.IsDarwin() {
			// Mach-O relocations are a royal pain to lay out.
			// They use a compact stateful bytecode representation.
			// Here we record what are needed and encode them later.
			ld.MachoAddRebase(s, int64(r.Off()))
			// Not mark r done here. So we still apply it statically,
			// so in the file content we'll also have the right offset
			// to the relocation target. So it can be examined statically
			// (e.g. go version).
			return true
		}
	case objabi.R_GOTPCREL:
		if target.IsExternal() {
			// External linker will do this relocation.
			return true
		}
		// We only need to handle external linking mode, as R_GOTPCREL can
		// only occur in plugin or shared build modes.
	}

	return false
}

func elfreloc1(ctxt *ld.Link, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, ri int, sectoff int64) bool {
	out.Write64(uint64(sectoff))

	elfsym := ld.ElfSymForReloc(ctxt, r.Xsym)
	siz := r.Size
	switch r.Type {
	default:
		return false
	case objabi.R_ADDR, objabi.R_DWARFSECREF:
		if siz == 4 {
			out.Write64(uint64(elf.R_X86_64_32) | uint64(elfsym)<<32)
		} else if siz == 8 {
			out.Write64(uint64(elf.R_X86_64_64) | uint64(elfsym)<<32)
		} else {
			return false
		}
	case objabi.R_TLS_LE:
		if siz == 4 {
			out.Write64(uint64(elf.R_X86_64_TPOFF32) | uint64(elfsym)<<32)
		} else {
			return false
		}
	case objabi.R_TLS_IE:
		if siz == 4 {
			out.Write64(uint64(elf.R_X86_64_GOTTPOFF) | uint64(elfsym)<<32)
		} else {
			return false
		}
	case objabi.R_CALL:
		if siz == 4 {
			if ldr.SymType(r.Xsym) == sym.SDYNIMPORT {
				out.Write64(uint64(elf.R_X86_64_PLT32) | uint64(elfsym)<<32)
			} else {
				out.Write64(uint64(elf.R_X86_64_PC32) | uint64(elfsym)<<32)
			}
		} else {
			return false
		}
	case objabi.R_PCREL:
		if siz == 4 {
			if ldr.SymType(r.Xsym) == sym.SDYNIMPORT && ldr.SymElfType(r.Xsym) == elf.STT_FUNC {
				out.Write64(uint64(elf.R_X86_64_PLT32) | uint64(elfsym)<<32)
			} else {
				out.Write64(uint64(elf.R_X86_64_PC32) | uint64(elfsym)<<32)
			}
		} else {
			return false
		}
	case objabi.R_GOTPCREL:
		if siz == 4 {
			out.Write64(uint64(elf.R_X86_64_GOTPCREL) | uint64(elfsym)<<32)
		} else {
			return false
		}
	}

	out.Write64(uint64(r.Xadd))
	return true
}

func machoreloc1(arch *sys.Arch, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, sectoff int64) bool {
	var v uint32

	rs := r.Xsym
	rt := r.Type

	if !ldr.SymType(s).IsDWARF() {
		if ldr.SymDynid(rs) < 0 {
			ldr.Errorf(s, "reloc %d (%s) to non-macho symbol %s type=%d (%s)", rt, sym.RelocName(arch, rt), ldr.SymName(rs), ldr.SymType(rs), ldr.SymType(rs))
			return false
		}

		v = uint32(ldr.SymDynid(rs))
		v |= 1 << 27 // external relocation
	} else {
		v = uint32(ldr.SymSect(rs).Extnum)
		if v == 0 {
			ldr.Errorf(s, "reloc %d (%s) to symbol %s in non-macho section %s type=%d (%s)", rt, sym.RelocName(arch, rt), ldr.SymName(rs), ldr.SymSect(rs).Name, ldr.SymType(rs), ldr.SymType(rs))
			return false
		}
	}

	switch rt {
	default:
		return false

	case objabi.R_ADDR:
		v |= ld.MACHO_X86_64_RELOC_UNSIGNED << 28

	case objabi.R_CALL:
		v |= 1 << 24 // pc-relative bit
		v |= ld.MACHO_X86_64_RELOC_BRANCH << 28

		// NOTE: Only works with 'external' relocation. Forced above.
	case objabi.R_PCREL:
		v |= 1 << 24 // pc-relative bit
		v |= ld.MACHO_X86_64_RELOC_SIGNED << 28
	case objabi.R_GOTPCREL:
		v |= 1 << 24 // pc-relative bit
		v |= ld.MACHO_X86_64_RELOC_GOT_LOAD << 28
	}

	switch r.Size {
	default:
		return false

	case 1:
		v |= 0 << 25

	case 2:
		v |= 1 << 25

	case 4:
		v |= 2 << 25

	case 8:
		v |= 3 << 25
	}

	out.Write32(uint32(sectoff))
	out.Write32(v)
	return true
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
		v = ld.IMAGE_REL_AMD64_SECREL

	case objabi.R_ADDR:
		if r.Size == 8 {
			v = ld.IMAGE_REL_AMD64_ADDR64
		} else {
			v = ld.IMAGE_REL_AMD64_ADDR32
		}

	case objabi.R_PEIMAGEOFF:
		v = ld.IMAGE_REL_AMD64_ADDR32NB

	case objabi.R_CALL,
		objabi.R_PCREL:
		v = ld.IMAGE_REL_AMD64_REL32
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
		// pushq got+8(IP)
		plt.AddUint8(0xff)

		plt.AddUint8(0x35)
		plt.AddPCRelPlus(ctxt.Arch, got.Sym(), 8)

		// jmpq got+16(IP)
		plt.AddUint8(0xff)

		plt.AddUint8(0x25)
		plt.AddPCRelPlus(ctxt.Arch, got.Sym(), 16)

		// nopl 0(AX)
		plt.AddUint32(ctxt.Arch, 0x00401f0f)

		// assume got->size == 0 too
		got.AddAddrPlus(ctxt.Arch, dynamic, 0)

		got.AddUint64(ctxt.Arch, 0)
		got.AddUint64(ctxt.Arch, 0)
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
		rela := ldr.MakeSymbolUpdater(syms.RelaPLT)
		if plt.Size() == 0 {
			panic("plt is not set up")
		}

		// jmpq *got+size(IP)
		plt.AddUint8(0xff)

		plt.AddUint8(0x25)
		plt.AddPCRelPlus(target.Arch, got.Sym(), got.Size())

		// add to got: pointer to current pos in plt
		got.AddAddrPlus(target.Arch, plt.Sym(), plt.Size())

		// pushq $x
		plt.AddUint8(0x68)

		plt.AddUint32(target.Arch, uint32((got.Size()-24-8)/8))

		// jmpq .plt
		plt.AddUint8(0xe9)

		plt.AddUint32(target.Arch, uint32(-(plt.Size() + 4)))

		// rela
		rela.AddAddrPlus(target.Arch, got.Sym(), got.Size()-8)

		sDynid := ldr.SymDynid(s)
		rela.AddUint64(target.Arch, elf.R_INFO(uint32(sDynid), uint32(elf.R_X86_64_JMP_SLOT)))
		rela.AddUint64(target.Arch, 0)

		ldr.SetPlt(s, int32(plt.Size()-16))
	} else if target.IsDarwin() {
		ld.AddGotSym(target, ldr, syms, s, 0)

		sDynid := ldr.SymDynid(s)
		lep := ldr.MakeSymbolUpdater(syms.LinkEditPLT)
		lep.AddUint32(target.Arch, uint32(sDynid))

		plt := ldr.MakeSymbolUpdater(syms.PLT)
		ldr.SetPlt(s, int32(plt.Size()))

		// jmpq *got+size(IP)
		plt.AddUint8(0xff)
		plt.AddUint8(0x25)
		plt.AddPCRelPlus(target.Arch, syms.GOT, int64(ldr.SymGot(s)))
	} else {
		ldr.Errorf(s, "addpltsym: unsupported binary format")
	}
}

func tlsIEtoLE(P []byte, off, size int) {
	// Transform the PC-relative instruction into a constant load.
	// That is,
	//
	//	MOVQ X(IP), REG  ->  MOVQ $Y, REG
	//
	// To determine the instruction and register, we study the op codes.
	// Consult an AMD64 instruction encoding guide to decipher this.
	if off < 3 {
		log.Fatal("R_X86_64_GOTTPOFF reloc not preceded by MOVQ or ADDQ instruction")
	}
	op := P[off-3 : off]
	reg := op[2] >> 3

	if op[1] == 0x8b || reg == 4 {
		// MOVQ
		if op[0] == 0x4c {
			op[0] = 0x49
		} else if size == 4 && op[0] == 0x44 {
			op[0] = 0x41
		}
		if op[1] == 0x8b {
			op[1] = 0xc7
		} else {
			op[1] = 0x81 // special case for SP
		}
		op[2] = 0xc0 | reg
	} else {
		// An alternate op is ADDQ. This is handled by GNU gold,
		// but right now is not generated by the Go compiler:
		//	ADDQ X(IP), REG  ->  ADDQ $Y, REG
		// Consider adding support for it here.
		log.Fatalf("expected TLS IE op to be MOVQ, got %v", op)
	}
}

"""



```