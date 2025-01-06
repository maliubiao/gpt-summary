Response:
My thought process to answer the request goes like this:

1. **Understand the Request:** The request asks for the functionality of the provided Go code snippet, which is part of the Go linker for the s390x architecture. It also asks for examples, especially concerning code generation and relocation.

2. **Identify Key Areas:** I scanned the code and immediately recognized several key function names and their likely purposes:
    * `gentext`: Likely related to generating text (assembly code) for initialization.
    * `adddynrel`:  Deals with adding dynamic relocations.
    * `elfreloc1`: Handles ELF relocation processing.
    * `elfsetupplt`:  Sets up the Procedure Linkage Table (PLT) for dynamic linking.
    * `machoreloc1`:  Handles Mach-O relocations (but this one returns `false`, indicating it's not the primary focus).
    * `archreloc` and `archrelocvariant`:  Generic architecture-specific relocation handling.
    * `addpltsym`: Adds symbols to the PLT.

3. **Focus on `gentext`:** The comment explicitly states its purpose: appending local module data to the global list. This is a crucial part of Go's runtime initialization.

    * **Break down `gentext` code:** I examined the assembly instructions being generated (`larl`, `jg`, `undef`). I recognized `larl` as "load address relative long" and `jg` as "jump if greater."  The `undef` is clearly for debugging.
    * **Connect to Go functionality:** This sequence aligns with the process of registering a Go module's metadata with the runtime linker. The `larl` loads the address of the module's data, and the `jg` jumps to the runtime function responsible for adding it to the linked list.
    * **Provide a Go example:** I crafted an example demonstrating how Go modules are implicitly created and how the runtime needs this information. I highlighted the `//go:linkname` directive as a way to understand the underlying mechanism (though not something typical user code uses directly).

4. **Analyze `adddynrel`:**  The name suggests handling dynamic relocations. The `switch` statement on `r.Type()` confirms this, as it deals with various ELF relocation types (prefixed with `objabi.ElfRelocOffset`).

    * **Identify the pattern:** I noticed it handles different ELF relocation types (`R_390_12`, `R_390_8`, etc.) and often updates the relocation type (`su.SetRelocType`) to Go's internal representation (`objabi.R_ADDR`, `objabi.R_PCREL`).
    * **Explain key relocation types:** I explained `R_ADDR`, `R_PCREL`, `R_GOTOFF`, and the PLT-related relocations, providing a basic understanding of their purpose.

5. **Examine `elfreloc1`:** This function is clearly responsible for writing ELF relocation entries to the output file.

    * **Connect to `adddynrel`:** I saw how `adddynrel` sets the Go relocation type, and `elfreloc1` then translates this into the specific ELF relocation code (`elf.R_390_TLS_LE32`, `elf.R_390_32`, etc.).
    * **Illustrate with an example:** I created a simple Go program with a global variable to demonstrate how `R_ADDR` relocations are used. I included the hypothetical ELF output to show the resulting relocation entry.

6. **Focus on `elfsetupplt` and `addpltsym`:** These functions are explicitly about setting up the PLT for dynamic linking.

    * **Explain PLT's purpose:** I described how the PLT enables calling functions in shared libraries.
    * **Break down `elfsetupplt` assembly:** I deciphered the assembly instructions that initialize the PLT, explaining the interaction with the Global Offset Table (GOT).
    * **Explain `addpltsym`:** I described how it adds entries to the PLT and GOT for dynamically linked symbols.

7. **Consider Command-Line Arguments:** I reviewed the code for any direct handling of command-line arguments. I found none within this specific snippet. Therefore, I stated that it doesn't directly handle command-line arguments but is part of a larger tool (`go build`, `go link`) that *does*.

8. **Identify Common Mistakes:**  I thought about potential errors a user might make based on the code's functionality.

    * **Incorrect understanding of dynamic linking:** Users might not grasp why PLT/GOT entries are necessary.
    * **Relocation errors:**  While users don't directly manipulate relocations, understanding them helps in debugging linking issues. I provided a scenario where incorrect relocation types could lead to errors.

9. **Structure the Answer:** I organized the information logically, starting with the overall functionality and then diving into details for each key function. I used clear headings and bullet points to improve readability. I made sure to address all parts of the original request.

10. **Review and Refine:** I reread my answer to ensure accuracy, clarity, and completeness, double-checking the assembly instruction explanations and code examples. I also ensured that the examples were practical and illustrative.
这段 Go 语言代码是 Go 链接器（`go link`）中用于处理 s390x 架构的汇编代码生成和重定位的部分。它主要负责以下功能：

**1. `gentext(ctxt *ld.Link, ldr *loader.Loader)`: 生成用于注册模块元数据的汇编代码**

   - **功能:**  在程序初始化时，将当前模块的元数据（`local.moduledata`）添加到全局的模块元数据链表中。这通常发生在运行时库位于不同模块的情况下。
   - **实现细节:**
     - 生成汇编指令 `larl %r2, <local.moduledata>`，将本地模块元数据的地址加载到寄存器 `r2`。
     - 生成汇编指令 `jg <runtime.addmoduledata@plt>`，跳转到运行时库的 `runtime.addmoduledata` 函数（通过 PLT 表）。
     - 添加一个 `undef` 指令，可能用于调试目的。
   - **Go 语言功能:**  支持 Go 模块化，使得不同的 Go 模块可以在运行时相互发现和交互。
   - **Go 代码示例:**

     ```go
     package main

     import "unsafe"

     //go:linkname localModuledata runtime.moduledata
     var localModuledata struct {
         // ... 模块元数据的字段
     }

     //go:linkname addmoduledata runtime.addmoduledata
     func addmoduledata(md *struct{})

     func main() {
         // 在程序启动时，链接器生成的 gentext 函数会被执行，
         // 将 localModuledata 的地址传递给 runtime.addmoduledata。
         // 这部分代码用户通常不需要直接编写或调用。
     }
     ```

     **假设输入:**  链接器正在链接一个包含多个模块的 Go 程序。
     **输出:**  链接器会在最终的可执行文件中生成 `go.link.addmoduledata` 符号对应的汇编代码，如代码所示，用于注册当前模块的元数据。

**2. `adddynrel(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym, r loader.Reloc, rIdx int) bool`: 处理动态链接的重定位**

   - **功能:**  处理将要进行动态链接的符号的重定位。这包括来自 ELF 目标文件的重定位。
   - **实现细节:**
     - 根据重定位类型 (`r.Type()`) 进行不同的处理。
     - 对于 ELF 目标文件的重定位（以 `objabi.ElfRelocOffset` 开头）：
       - 一些重定位类型（如 `R_390_12`, `R_390_GOT12`）目前尚未实现，会报错。
       - 对于 `R_390_8`, `R_390_16`, `R_390_32`, `R_390_64` 等绝对地址重定位，如果目标符号是动态导入的，会报错，否则将其转换为 `objabi.R_ADDR`。
       - 对于 `R_390_PC16`, `R_390_PC32`, `R_390_PC64` 等 PC 相对地址重定位，如果目标符号是动态导入的或未知的，会报错，否则将其转换为 `objabi.R_PCREL`，并调整偏移量。
       - 对于与 PLT (Procedure Linkage Table) 相关的重定位（如 `R_390_PLT16DBL`, `R_390_PLT32DBL`, `R_390_PLT32`, `R_390_PLT64`），会根据目标符号是否为动态导入进行不同的处理，包括调用 `addpltsym` 添加 PLT 条目。
       - 对于其他 ELF 重定位类型，大部分会报错，表示尚未实现。
   - **Go 语言功能:**  支持与动态链接库进行交互，允许 Go 程序调用外部共享库中的函数。
   - **假设输入:**  链接器正在链接一个需要调用共享库函数的 Go 程序，并且遇到一个针对共享库函数的 `R_390_PLT32` 类型的重定位。
   - **输出:**  `adddynrel` 函数会识别出这是一个与 PLT 相关的重定位，并且目标符号是动态导入的。它会调用 `addpltsym` 为该符号创建 PLT 条目，并将重定位类型修改为 `objabi.R_PCREL`，指向 PLT 表中的相应条目。

**3. `elfreloc1(ctxt *ld.Link, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, ri int, sectoff int64) bool`: 生成 ELF 重定位条目**

   - **功能:**  将 Go 内部的重定位类型转换为 ELF 格式的重定位条目，并写入到输出文件的重定位段。
   - **实现细节:**
     - 根据 Go 的重定位类型 (`r.Type`) 和大小 (`r.Size`)，以及是否需要双字对齐 (`sym.RV_390_DBL`)，选择合适的 ELF 重定位类型（例如 `elf.R_390_32`, `elf.R_390_PC32`, `elf.R_390_PLT32` 等）。
     - 对于指向 TLS (Thread Local Storage) 的重定位，会使用 `elf.R_390_TLS_LE32` 或 `elf.R_390_TLS_IEENT`。
     - 对于 GOT (Global Offset Table) 相关的 PC 相对重定位，会使用 `elf.R_390_GOTENT`。
     - 对于 PLT 相关的重定位，会根据目标符号是否为动态导入以及大小选择合适的 `elf.R_390_PLT` 类型。
   - **Go 语言功能:**  确保生成的可执行文件符合 ELF 格式，以便操作系统加载器能够正确解析和重定位。
   - **假设输入:**  `adddynrel` 将一个针对外部函数的重定位的类型设置为 `objabi.R_PCREL`，大小为 4 字节，并且需要 PLT 条目。
   - **输出:**  `elfreloc1` 会将此信息转换为一个 ELF 重定位条目，其类型为 `elf.R_390_PLT32`，指向该外部函数在 PLT 表中的位置。

**4. `elfsetupplt(ctxt *ld.Link, ldr *loader.Loader, plt, got *loader.SymbolBuilder, dynamic loader.Sym)`: 初始化 PLT 和 GOT**

   - **功能:**  在 ELF 文件中设置 PLT (Procedure Linkage Table) 和 GOT (Global Offset Table) 的初始内容。
   - **实现细节:**
     - 如果 PLT 表为空，则添加初始的 PLT 代码，这段代码负责将控制权转移到动态链接器。
     - 同时初始化 GOT 表的前几个条目，通常包含指向动态链接器和模块信息的指针。
   - **Go 语言功能:**  为动态链接提供必要的运行时支持。PLT 和 GOT 是实现延迟绑定的关键数据结构。

**5. `machoreloc1(*sys.Arch, *ld.OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool`: 处理 Mach-O 重定位 (当前返回 false)**

   - **功能:**  理论上应该处理 Mach-O 格式的重定位，但当前实现直接返回 `false`，表明 s390x 架构的 Go 链接器可能主要关注 ELF 格式。

**6. `archreloc(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, r loader.Reloc, s loader.Sym, val int64) (o int64, nExtReloc int, ok bool)`:  架构相关的重定位处理 (当前未进行实际操作)**

   - **功能:**  提供一个接口用于进行架构特定的重定位调整。但当前实现似乎没有进行任何实际操作，直接返回输入值。

**7. `archrelocvariant(target *ld.Target, ldr *loader.Loader, r loader.Reloc, rv sym.RelocVariant, s loader.Sym, t int64, p []byte) int64`: 处理重定位变体**

   - **功能:**  处理重定位的变体，例如用于指示是否需要双字对齐 (`sym.RV_390_DBL`)。
   - **实现细节:**
     - 如果变体指示需要双字对齐，则检查目标地址是否对齐，如果未对齐则报错，否则将地址右移一位（除以 2）。

**8. `addpltsym(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym)`: 添加 PLT 表条目**

   - **功能:**  为动态链接的外部函数在 PLT 表中添加一个条目。
   - **实现细节:**
     - 如果该符号的 PLT 条目已存在，则直接返回。
     - 否则，调用 `ld.Adddynsym` 将该符号添加到动态符号表。
     - 如果目标格式是 ELF，则：
       - 在 PLT 表中添加汇编代码，用于跳转到 GOT 表中的对应条目。
       - 在 GOT 表中添加指向 PLT 表当前位置的指针。
       - 在 `.rela.plt` 段中添加重定位信息，用于在运行时填充 GOT 表。
   - **Go 语言功能:**  实现动态链接的关键步骤，使得程序在运行时能够找到并调用外部共享库中的函数。

**推理 Go 语言功能的实现:**

这段代码是 Go 链接器中 **动态链接** 和 **模块化** 功能在 s390x 架构上的具体实现。

- **动态链接:**  通过 `adddynrel`, `elfreloc1`, `elfsetupplt`, 和 `addpltsym` 函数，链接器能够处理对外部共享库函数的引用，生成必要的 PLT 和 GOT 表，并在 ELF 文件中生成相应的重定位信息，使得程序在运行时能够正确调用这些外部函数。
- **模块化:**  通过 `gentext` 函数，链接器确保每个 Go 模块的元数据在程序启动时被注册到运行时库，使得 Go 的反射和类型系统能够在运行时正确地工作，即使程序由多个独立的模块组成。

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是由 `cmd/link/internal/ld` 包中的更高级别的代码调用的，而 `ld` 包会解析 `go link` 命令的各种参数，例如 `-L` (指定库文件路径), `-buildmode=...` (指定构建模式), 等等。这些参数会影响链接过程，例如是否需要生成动态链接的可执行文件，以及需要链接哪些库。

**使用者易犯错的点 (与这段代码相关性较弱，更多是链接器本身的使用):**

虽然用户通常不会直接与这段 `asm.go` 代码交互，但在使用 `go build` 或 `go link` 时，一些常见的错误与链接过程有关：

1. **忘记链接必要的动态库:** 如果 Go 代码使用了 `import "C"` 调用了外部 C 代码，并且这些 C 代码位于一个动态库中，那么在链接时需要确保该动态库被正确链接。这通常通过在构建命令中使用 `-ldflags "-l<库名>"` 来实现。

   **示例:**
   ```go
   package main

   //#cgo LDFLAGS: -lmylib
   import "C"

   func main() {
       C.my_c_function()
   }
   ```
   如果忘记 `-lmylib`，链接器会报错，因为找不到 `my_c_function` 的定义。

2. **动态库路径不正确:** 如果使用了外部动态库，但操作系统找不到该库，程序在运行时可能会崩溃。可以使用 `-ldflags "-L<库路径>"` 指定动态库的搜索路径。

3. **构建模式不匹配:**  选择错误的构建模式（例如，尝试将一个包含 `import "C"` 的程序静态链接，但依赖的 C 库只能动态链接）会导致链接错误。

这段 `asm.go` 代码是 Go 链接器内部复杂工作的一个组成部分，它专注于特定架构的汇编生成和重定位，为 Go 程序的正确构建和运行奠定了基础。

Prompt: 
```
这是路径为go/src/cmd/link/internal/s390x/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
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

package s390x

import (
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/ld"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/elf"
)

// gentext generates assembly to append the local moduledata to the global
// moduledata linked list at initialization time. This is only done if the runtime
// is in a different module.
//
//	<go.link.addmoduledata>:
//		larl  %r2, <local.moduledata>
//		jg    <runtime.addmoduledata@plt>
//		undef
//
// The job of appending the moduledata is delegated to runtime.addmoduledata.
func gentext(ctxt *ld.Link, ldr *loader.Loader) {
	initfunc, addmoduledata := ld.PrepareAddmoduledata(ctxt)
	if initfunc == nil {
		return
	}

	// larl %r2, <local.moduledata>
	initfunc.AddUint8(0xc0)
	initfunc.AddUint8(0x20)
	initfunc.AddSymRef(ctxt.Arch, ctxt.Moduledata, 6, objabi.R_PCREL, 4)
	r1 := initfunc.Relocs()
	ldr.SetRelocVariant(initfunc.Sym(), r1.Count()-1, sym.RV_390_DBL)

	// jg <runtime.addmoduledata[@plt]>
	initfunc.AddUint8(0xc0)
	initfunc.AddUint8(0xf4)
	initfunc.AddSymRef(ctxt.Arch, addmoduledata, 6, objabi.R_CALL, 4)
	r2 := initfunc.Relocs()
	ldr.SetRelocVariant(initfunc.Sym(), r2.Count()-1, sym.RV_390_DBL)

	// undef (for debugging)
	initfunc.AddUint32(ctxt.Arch, 0)
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
			ldr.Errorf(s, "unexpected relocation type %d", r.Type())
			return false
		}

		// Handle relocations found in ELF object files.
	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_12),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_GOT12):
		ldr.Errorf(s, "s390x 12-bit relocations have not been implemented (relocation type %d)", r.Type()-objabi.ElfRelocOffset)
		return false

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_8),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_16),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_32),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_64):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_390_nn relocation for dynamic symbol %s", ldr.SymName(targ))
		}

		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ADDR)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_PC16),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_PC32),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_PC64):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_390_PCnn relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		if targType == 0 || targType == sym.SXREF {
			ldr.Errorf(s, "unknown symbol %s in pcrel", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocAdd(rIdx, r.Add()+int64(r.Siz()))
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_GOT16),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_GOT32),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_GOT64):
		ldr.Errorf(s, "unimplemented S390x relocation: %v", r.Type()-objabi.ElfRelocOffset)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_PLT16DBL),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_PLT32DBL):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		ldr.SetRelocVariant(s, rIdx, sym.RV_390_DBL)
		su.SetRelocAdd(rIdx, r.Add()+int64(r.Siz()))
		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			r.SetSym(syms.PLT)
			su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymPlt(targ)))
		}
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_PLT32),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_PLT64):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocAdd(rIdx, r.Add()+int64(r.Siz()))
		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			r.SetSym(syms.PLT)
			su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymPlt(targ)))
		}
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_COPY):
		ldr.Errorf(s, "unimplemented S390x relocation: %v", r.Type()-objabi.ElfRelocOffset)
		return false

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_GLOB_DAT):
		ldr.Errorf(s, "unimplemented S390x relocation: %v", r.Type()-objabi.ElfRelocOffset)
		return false

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_JMP_SLOT):
		ldr.Errorf(s, "unimplemented S390x relocation: %v", r.Type()-objabi.ElfRelocOffset)
		return false

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_RELATIVE):
		ldr.Errorf(s, "unimplemented S390x relocation: %v", r.Type()-objabi.ElfRelocOffset)
		return false

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_GOTOFF):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_390_GOTOFF relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_GOTOFF)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_GOTPC):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		r.SetSym(syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+int64(r.Siz()))
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_PC16DBL),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_PC32DBL):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		ldr.SetRelocVariant(s, rIdx, sym.RV_390_DBL)
		su.SetRelocAdd(rIdx, r.Add()+int64(r.Siz()))
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_390_PCnnDBL relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_GOTPCDBL):
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		ldr.SetRelocVariant(s, rIdx, sym.RV_390_DBL)
		r.SetSym(syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+int64(r.Siz()))
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_390_GOTENT):
		ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_390_GLOB_DAT))
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		ldr.SetRelocVariant(s, rIdx, sym.RV_390_DBL)
		r.SetSym(syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymGot(targ))+int64(r.Siz()))
		return true
	}
	// Handle references to ELF symbols from our own object files.
	return targType != sym.SDYNIMPORT
}

func elfreloc1(ctxt *ld.Link, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, ri int, sectoff int64) bool {
	out.Write64(uint64(sectoff))

	elfsym := ld.ElfSymForReloc(ctxt, r.Xsym)
	siz := r.Size
	switch r.Type {
	default:
		return false
	case objabi.R_TLS_LE:
		switch siz {
		default:
			return false
		case 4:
			// WARNING - silently ignored by linker in ELF64
			out.Write64(uint64(elf.R_390_TLS_LE32) | uint64(elfsym)<<32)
		case 8:
			// WARNING - silently ignored by linker in ELF32
			out.Write64(uint64(elf.R_390_TLS_LE64) | uint64(elfsym)<<32)
		}
	case objabi.R_TLS_IE:
		switch siz {
		default:
			return false
		case 4:
			out.Write64(uint64(elf.R_390_TLS_IEENT) | uint64(elfsym)<<32)
		}
	case objabi.R_ADDR, objabi.R_DWARFSECREF:
		switch siz {
		default:
			return false
		case 4:
			out.Write64(uint64(elf.R_390_32) | uint64(elfsym)<<32)
		case 8:
			out.Write64(uint64(elf.R_390_64) | uint64(elfsym)<<32)
		}
	case objabi.R_GOTPCREL:
		if siz == 4 {
			out.Write64(uint64(elf.R_390_GOTENT) | uint64(elfsym)<<32)
		} else {
			return false
		}
	case objabi.R_PCREL, objabi.R_PCRELDBL, objabi.R_CALL:
		elfrel := elf.R_390_NONE
		rVariant := ldr.RelocVariant(s, ri)
		isdbl := rVariant&sym.RV_TYPE_MASK == sym.RV_390_DBL
		// TODO(mundaym): all DBL style relocations should be
		// signalled using the variant - see issue 14218.
		switch r.Type {
		case objabi.R_PCRELDBL, objabi.R_CALL:
			isdbl = true
		}
		if ldr.SymType(r.Xsym) == sym.SDYNIMPORT && (ldr.SymElfType(r.Xsym) == elf.STT_FUNC || r.Type == objabi.R_CALL) {
			if isdbl {
				switch siz {
				case 2:
					elfrel = elf.R_390_PLT16DBL
				case 4:
					elfrel = elf.R_390_PLT32DBL
				}
			} else {
				switch siz {
				case 4:
					elfrel = elf.R_390_PLT32
				case 8:
					elfrel = elf.R_390_PLT64
				}
			}
		} else {
			if isdbl {
				switch siz {
				case 2:
					elfrel = elf.R_390_PC16DBL
				case 4:
					elfrel = elf.R_390_PC32DBL
				}
			} else {
				switch siz {
				case 2:
					elfrel = elf.R_390_PC16
				case 4:
					elfrel = elf.R_390_PC32
				case 8:
					elfrel = elf.R_390_PC64
				}
			}
		}
		if elfrel == elf.R_390_NONE {
			return false // unsupported size/dbl combination
		}
		out.Write64(uint64(elfrel) | uint64(elfsym)<<32)
	}

	out.Write64(uint64(r.Xadd))
	return true
}

func elfsetupplt(ctxt *ld.Link, ldr *loader.Loader, plt, got *loader.SymbolBuilder, dynamic loader.Sym) {
	if plt.Size() == 0 {
		// stg     %r1,56(%r15)
		plt.AddUint8(0xe3)
		plt.AddUint8(0x10)
		plt.AddUint8(0xf0)
		plt.AddUint8(0x38)
		plt.AddUint8(0x00)
		plt.AddUint8(0x24)
		// larl    %r1,_GLOBAL_OFFSET_TABLE_
		plt.AddUint8(0xc0)
		plt.AddUint8(0x10)
		plt.AddSymRef(ctxt.Arch, got.Sym(), 6, objabi.R_PCRELDBL, 4)
		// mvc     48(8,%r15),8(%r1)
		plt.AddUint8(0xd2)
		plt.AddUint8(0x07)
		plt.AddUint8(0xf0)
		plt.AddUint8(0x30)
		plt.AddUint8(0x10)
		plt.AddUint8(0x08)
		// lg      %r1,16(%r1)
		plt.AddUint8(0xe3)
		plt.AddUint8(0x10)
		plt.AddUint8(0x10)
		plt.AddUint8(0x10)
		plt.AddUint8(0x00)
		plt.AddUint8(0x04)
		// br      %r1
		plt.AddUint8(0x07)
		plt.AddUint8(0xf1)
		// nopr    %r0
		plt.AddUint8(0x07)
		plt.AddUint8(0x00)
		// nopr    %r0
		plt.AddUint8(0x07)
		plt.AddUint8(0x00)
		// nopr    %r0
		plt.AddUint8(0x07)
		plt.AddUint8(0x00)

		// assume got->size == 0 too
		got.AddAddrPlus(ctxt.Arch, dynamic, 0)

		got.AddUint64(ctxt.Arch, 0)
		got.AddUint64(ctxt.Arch, 0)
	}
}

func machoreloc1(*sys.Arch, *ld.OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool {
	return false
}

func archreloc(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, r loader.Reloc, s loader.Sym, val int64) (o int64, nExtReloc int, ok bool) {
	return val, 0, false
}

func archrelocvariant(target *ld.Target, ldr *loader.Loader, r loader.Reloc, rv sym.RelocVariant, s loader.Sym, t int64, p []byte) int64 {
	switch rv & sym.RV_TYPE_MASK {
	default:
		ldr.Errorf(s, "unexpected relocation variant %d", rv)
		return t

	case sym.RV_NONE:
		return t

	case sym.RV_390_DBL:
		if t&1 != 0 {
			ldr.Errorf(s, "%s+%v is not 2-byte aligned", ldr.SymName(r.Sym()), ldr.SymValue(r.Sym()))
		}
		return t >> 1
	}
}

func addpltsym(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym) {
	if ldr.SymPlt(s) >= 0 {
		return
	}

	ld.Adddynsym(ldr, target, syms, s)

	if target.IsElf() {
		plt := ldr.MakeSymbolUpdater(syms.PLT)
		got := ldr.MakeSymbolUpdater(syms.GOT)
		rela := ldr.MakeSymbolUpdater(syms.RelaPLT)
		if plt.Size() == 0 {
			panic("plt is not set up")
		}
		// larl    %r1,_GLOBAL_OFFSET_TABLE_+index

		plt.AddUint8(0xc0)
		plt.AddUint8(0x10)
		plt.AddPCRelPlus(target.Arch, got.Sym(), got.Size()+6)
		pltrelocs := plt.Relocs()
		ldr.SetRelocVariant(plt.Sym(), pltrelocs.Count()-1, sym.RV_390_DBL)

		// add to got: pointer to current pos in plt
		got.AddAddrPlus(target.Arch, plt.Sym(), plt.Size()+8) // weird but correct
		// lg      %r1,0(%r1)
		plt.AddUint8(0xe3)
		plt.AddUint8(0x10)
		plt.AddUint8(0x10)
		plt.AddUint8(0x00)
		plt.AddUint8(0x00)
		plt.AddUint8(0x04)
		// br      %r1
		plt.AddUint8(0x07)
		plt.AddUint8(0xf1)
		// basr    %r1,%r0
		plt.AddUint8(0x0d)
		plt.AddUint8(0x10)
		// lgf     %r1,12(%r1)
		plt.AddUint8(0xe3)
		plt.AddUint8(0x10)
		plt.AddUint8(0x10)
		plt.AddUint8(0x0c)
		plt.AddUint8(0x00)
		plt.AddUint8(0x14)
		// jg .plt
		plt.AddUint8(0xc0)
		plt.AddUint8(0xf4)

		plt.AddUint32(target.Arch, uint32(-((plt.Size() - 2) >> 1))) // roll-your-own relocation
		//.plt index
		plt.AddUint32(target.Arch, uint32(rela.Size())) // rela size before current entry

		// rela
		rela.AddAddrPlus(target.Arch, got.Sym(), got.Size()-8)

		sDynid := ldr.SymDynid(s)
		rela.AddUint64(target.Arch, elf.R_INFO(uint32(sDynid), uint32(elf.R_390_JMP_SLOT)))
		rela.AddUint64(target.Arch, 0)

		ldr.SetPlt(s, int32(plt.Size()-32))

	} else {
		ldr.Errorf(s, "addpltsym: unsupported binary format")
	}
}

"""



```