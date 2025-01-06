Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keywords:**

The first step is to quickly scan the code for recognizable keywords and structures. We see:

* `package mips64`:  This immediately tells us this code is specific to the MIPS64 architecture.
* `import`: A list of standard Go packages related to linking and ELF format. This strongly suggests the code is involved in the linking process for MIPS64 executables.
* `var`: Global variables like `dtOffsets`, `dynSymCount`, `gotLocalCount`, `gotSymIndex`. These look like counters and data structures related to the dynamic linking process.
* `func`: Several functions with names like `gentext`, `adddynrel`, `elfreloc1`, `elfsetupplt`, `addpltsym`, `archreloc`, `extreloc`. These sound like stages in the linking process, especially given the "reloc" prefixes which hint at relocation handling.
* `elf.DT_...`:  Constants from the `debug/elf` package. These are tags used in the ELF dynamic section.
* `objabi.R_...`: Constants from `cmd/internal/objabi`. These are relocation types specific to the Go object file format.
* `ld.*`:  Functions and types from `cmd/link/internal/ld`, the Go linker.
* `loader.*`: Functions and types from `cmd/link/internal/loader`, the linker's object file loader.
* `sym.*`: Functions and types from `cmd/link/internal/sym`, representing symbols.
* Comments referencing "Inferno utils/5l/asm.c": This points to the historical roots of the code and its low-level nature.

**2. Inferring Core Functionality (The "Big Picture"):**

Based on the imports, function names, and the MIPS64 package, a high-level guess is that this code handles the architecture-specific parts of linking Go programs for MIPS64 systems, particularly focusing on generating the necessary information for dynamic linking (shared libraries).

**3. Analyzing Individual Functions and Variables:**

Now, let's delve into the individual components:

* **Global Variables:** The names clearly suggest their purpose. `dtOffsets` stores offsets within the `.dynamic` section. The `got...` variables track information about the Global Offset Table (GOT), which is crucial for dynamic linking. `dynSymCount` is related to the dynamic symbol table.

* **`gentext`:** This function seems to generate entries for the `.dynamic` section of the ELF file. It writes entries like `DT_MIPS_RLD_VERSION` and `DT_MIPS_BASE_ADDRESS`. It also initializes `dtOffsets` for later updates. The check for `gotLocalCount == 0` suggests a dependency on `elfsetupplt`.

* **`adddynrel`:** This function appears to handle dynamic relocations. The `R_CALLMIPS` and `R_JMPMIPS` cases are interesting, specifically how they handle external symbols by creating PLT (Procedure Linkage Table) entries.

* **`elfreloc1`:**  This function seems to be responsible for writing out the actual ELF relocation entries in the `.rela.dyn` section. The structure of the output (`out.Write64`, `out.Write32`, `out.Write8`) matches the ELF relocation format for MIPS64. The `switch` statement handles different relocation types.

* **`elfsetupplt`:**  This is a key function for setting up the PLT. It initializes the first few entries in the `.plt` and `.got.plt` sections. The assembly-like instructions (e.g., `lui`, `ld`, `jalr`) are used to create the initial PLT stub. The increment of `gotLocalCount` makes sense here.

* **`addpltsym`:** This function adds a new entry to the PLT for a given external symbol. It updates `gotSymIndex` and `dynSymCount`. It also generates the code within the PLT to jump to the correct GOT entry and the code to populate the GOT entry itself.

* **`archreloc`:** This function handles architecture-specific relocation calculations when *not* using an external linker. It performs calculations for different MIPS relocation types (`R_ADDRMIPS`, `R_ADDRMIPSU`, `R_ADDRMIPSTLS`, `R_CALLMIPS`, `R_JMPMIPS`). The TLS offset handling is noteworthy.

* **`extreloc`:** This function decides whether a given relocation needs to be handled by an external linker (if one is used).

**4. Connecting the Dots and Forming the Narrative:**

By analyzing the individual parts, we can piece together the overall functionality:

* **Dynamic Linking Support:** The code is heavily involved in generating the `.dynamic` section, the PLT, and the GOT, all essential components for dynamic linking in ELF binaries.
* **Relocation Handling:** Functions like `adddynrel`, `elfreloc1`, and `archreloc` are responsible for managing different types of relocations, both for internal and external linking.
* **MIPS64 Specifics:**  The code uses MIPS64-specific relocation types (e.g., `R_MIPS_LO16`, `R_MIPS_HI16`, `R_MIPS_26`) and generates MIPS assembly instructions in `elfsetupplt` and `addpltsym`.
* **Internal vs. External Linking:** The code handles both scenarios, with `adddynrel` and `archreloc` showing conditional logic based on whether an external linker is used.

**5. Generating Examples and Identifying Potential Issues:**

Based on the understanding of the code, we can start constructing examples. For instance, the PLT setup in `elfsetupplt` can be illustrated with a simple program calling a function from a shared library. Potential issues arise in relocation calculations (e.g., TLS offsets) and the interaction with external linkers.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "This might be just about assembly."  **Correction:**  The ELF and dynamic linking aspects are very strong, indicating it's about the *linking* process, not just assembly generation.
* **Initial thought:** "The `gentext` function generates the entire `.dynamic` section." **Correction:** It seems to initialize some entries and sets up placeholders, while other functions like `addpltsym` might also contribute.
* **Noticing the "OpenBSD" special case:** This highlights platform-specific adjustments needed during linking, particularly for TLS.

By following this kind of structured analysis, combining keyword recognition, functional decomposition, and understanding the underlying concepts (like ELF and dynamic linking), one can effectively decipher the purpose and workings of even complex code snippets.
这段Go语言代码是Go编译器 `cmd/link` 工具中，用于处理 **MIPS64 架构** 链接过程中的汇编相关的部分。它的主要功能是：

**1. 生成 ELF 动态链接所需的 `.dynamic` 段信息 (gentext 函数):**

   - 对于需要动态链接的可执行文件或共享库，它负责生成 `.dynamic` 段的条目，这些条目包含了动态链接器需要的信息。
   - 它会写入一些 MIPS 特有的 `DT_MIPS_*` 类型的 tag，例如：
     - `DT_MIPS_RLD_VERSION`:  MIPS 重定位器版本。
     - `DT_MIPS_BASE_ADDRESS`:  程序的基地址 (通常为 0)。
     - `DT_MIPS_LOCAL_GOTNO`:  本地 GOT 表项的数量。
     - `DT_MIPS_SYMTABNO`:  动态符号表项的数量。
     - `DT_MIPS_GOTSYM`:  GOT 表对应的第一个动态符号表项的索引。
   - 这些值有些在此时就能确定，有些则需要在后续的链接阶段才能确定，因此代码中使用了 `dtOffsets` 来记录需要后续更新的条目的偏移量。

**2. 处理动态链接重定位 (adddynrel 函数):**

   - 当遇到需要动态链接的符号时，这个函数会进行处理。
   - 特别地，对于 `R_CALLMIPS` 和 `R_JMPMIPS` 类型的重定位 (通常用于函数调用)，如果目标符号是动态导入的 (来自共享库)，它会：
     - 创建一个 PLT (Procedure Linkage Table) 条目。
     - 将重定位目标修改为指向 PLT 条目。
     - 这使得在运行时可以通过 PLT 来解析并调用共享库中的函数。

**3. 生成 ELF 重定位条目 (elfreloc1 函数):**

   - 这个函数负责生成实际的 ELF 重定位条目，这些条目存储在 `.rela.dyn` 或 `.rela.plt` 段中。
   - 它根据不同的重定位类型 (`r.Type`) 和大小 (`r.Size`)，以及目标架构 (`ctxt.Arch`)，写入不同格式的重定位信息。
   - 例如，对于地址相关的重定位，会写入 `R_MIPS_32` 或 `R_MIPS_64` 等类型的条目。对于 PC 相对跳转，会写入 `R_MIPS_26` 类型的条目。
   - 特别地，它还处理了 MIPS TLS (Thread Local Storage) 相关的重定位类型 `R_MIPS_TLS_TPREL_LO16`，并考虑了 OpenBSD 平台的特殊性。

**4. 设置 PLT (Procedure Linkage Table) (elfsetupplt 函数):**

   - 这个函数负责初始化 PLT 和 GOT (Global Offset Table) 中与 PLT 相关的部分。
   - 它会生成 PLT 的第一部分代码，这段代码负责跳转到动态链接器的解析器。
   - 它会在 GOT 中预留前两个条目：
     - `got[0]`: 用于存储动态链接器的地址。
     - `got[1]`: 用于存储指向 ELF 对象的指针。
   - 它还会递增 `gotLocalCount`，记录本地 GOT 表项的数量。

**5. 添加 PLT 符号 (addpltsym 函数):**

   - 当需要为某个动态导入的符号创建 PLT 条目时，这个函数会被调用。
   - 它会分配一个新的 PLT 条目，并在其中生成跳转到对应 GOT 表项的代码。
   - 它还会更新 GOT 表，将新 PLT 条目的地址放入其中。
   - 同时，它会更新 `dynSymCount` 和 `gotSymIndex`，以反映 PLT 的添加。

**6. 处理架构相关的重定位值计算 (archreloc 函数):**

   - 这个函数在内部链接时被调用，用于计算特定重定位类型的值。
   - 它处理例如 `R_ADDRMIPS` (低 16 位地址), `R_ADDRMIPSU` (高 16 位地址), `R_ADDRMIPSTLS` (TLS 地址), `R_CALLMIPS`, `R_JMPMIPS` 等重定位类型。
   - 对于 TLS 相关的重定位，它会考虑到 MIPS 的 TLS 偏移量 (通常是 0x7000)，并处理 OpenBSD 的特殊情况。
   - 对于 `R_CALLMIPS` 和 `R_JMPMIPS`，它会计算目标地址的低 26 位。

**7. 判断是否需要外部重定位 (extreloc 函数):**

   - 这个函数判断某些类型的重定位是否需要交给外部链接器处理。
   - 对于地址相关的重定位，它通常会使用外部符号。

**推理 Go 语言功能实现:**

这段代码主要实现了 Go 语言中 **动态链接** 的功能在 MIPS64 架构上的具体细节。当 Go 程序需要调用外部的 C 共享库时，就需要用到动态链接。

**Go 代码示例:**

```go
package main

import "C"

//export SomeFunctionFromGo
func SomeFunctionFromGo() {
	// ... 一些 Go 代码 ...
}

func main() {
	// 调用 C 共享库中的函数
	C.printf(C.CString("Hello from Go!\n"))
}
```

**假设输入与输出 (针对 `addpltsym` 函数):**

**假设输入:**

- `target`:  MIPS64 架构的目标信息。
- `ldr`:  链接器 Loader 对象。
- `syms`:  包含架构特定符号的结构体，例如 `syms.PLT`, `syms.GOTPLT`, `syms.Dynamic`, `syms.DynSym`。
- `s`:  一个动态导入的外部符号 (例如 `C.printf`) 的 Loader Symbol。

**假设输出:**

- 在 `.plt` 段 (由 `syms.PLT` 表示) 中新增了一段代码，用于跳转到 `C.printf` 的 GOT 条目。
- 在 `.got.plt` 段 (由 `syms.GOTPLT` 表示) 中新增了一个条目，存储了 `.plt` 中新增代码的地址。
- `ldr.SymPlt(s)` 的返回值变为新分配的 PLT 条目的偏移量。
- `syms.Dynamic` 符号的内容被更新，增加了 `DT_MIPS_SYMTABNO` 的值。

**代码推理示例 (`addpltsym` 函数片段):**

```go
	plt := ldr.MakeSymbolUpdater(syms.PLT)
	gotplt := ldr.MakeSymbolUpdater(syms.GOTPLT)
	// ... (假设 plt.Size() 当前为 16) ...

	// Load got.plt entry into r25.
	plt.AddSymRef(target.Arch, gotplt.Sym(), gotplt.Size(), objabi.R_ADDRMIPSU, 4)
	plt.SetUint32(target.Arch, plt.Size()-4, 0x3c0f0000) // lui   $15, %hi(.got.plt entry)
	plt.AddSymRef(target.Arch, gotplt.Sym(), gotplt.Size(), objabi.R_ADDRMIPS, 4)
	plt.SetUint32(target.Arch, plt.Size()-4, 0xddf90000) // ld    $25, %lo(.got.plt entry)($15)

	// ... (假设 gotplt.Size() 当前为 8) ...
	gotplt.AddAddrPlus(target.Arch, plt.Sym(), 0)
```

**推理过程:**

1. `plt` 和 `gotplt` 分别代表 `.plt` 和 `.got.plt` 段的符号。
2. 代码开始时，`plt.Size()` 假设为 16 (已经有初始的 PLT 代码)。
3. `plt.AddSymRef` 和 `plt.SetUint32` 组合起来，在 `.plt` 中添加了 MIPS64 指令，用于加载 `gotplt` 中下一个空闲条目的地址到寄存器 `$25`。
   - `0x3c0f0000` 是 `lui $15, %hi(.got.plt entry)` 的机器码，将 `.got.plt` 条目的高 16 位加载到 `$15`。
   - `0xddf90000` 是 `ld $25, %lo(.got.plt entry)($15)` 的机器码，将 `.got.plt` 条目的低 16 位与 `$15` 组合，并加载到 `$25`。
4. `gotplt.AddAddrPlus` 在 `.got.plt` 中添加一个 64 位地址，这个地址是 `plt.Sym()`，也就是新创建的 PLT 代码的起始地址。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。命令行参数的处理发生在 `cmd/link/internal/ld` 包中的更上层逻辑。但是，链接器的命令行参数会影响这段代码的行为。例如：

- `-buildmode=c-shared`:  如果使用此参数构建共享库，`gentext` 函数就会被调用，生成 `.dynamic` 段。
- `-linkshared`:  如果需要链接共享库，`adddynrel` 和 `addpltsym` 等函数会被调用，处理动态链接相关的重定位。
- 目标架构相关的参数 (例如 `-target=linux/mips64`) 会决定这段代码是否会被使用。

**使用者易犯错的点 (不涉及，因为这是链接器内部代码):**

这段代码是 Go 链接器的内部实现，开发者通常不会直接接触或修改它。因此，对于一般的 Go 语言使用者来说，不存在易犯错的点。  这里的错误通常是链接器开发者需要注意的，例如：

- **重定位类型的错误匹配:**  在 `elfreloc1` 中，如果 `r.Type` 和写入的 ELF 重定位类型不匹配，会导致链接错误或运行时错误。
- **PLT 和 GOT 的错误设置:**  `elfsetupplt` 和 `addpltsym` 中的代码如果出现错误，会导致动态链接失败。
- **TLS 偏移量的错误处理:** `archreloc` 中关于 TLS 偏移量的处理需要特别注意平台差异。

总而言之，这段代码是 Go 链接器针对 MIPS64 架构进行底层处理的关键部分，它确保了 Go 程序能够正确地链接和执行，特别是涉及动态链接时。

Prompt: 
```
这是路径为go/src/cmd/link/internal/mips64/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package mips64

import (
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/ld"
	"cmd/link/internal/loader"
	"cmd/link/internal/sym"
	"debug/elf"
)

var (
	// dtOffsets contains offsets for entries within the .dynamic section.
	// These are used to fix up symbol values once they are known.
	dtOffsets map[elf.DynTag]int64

	// dynSymCount contains the number of entries in the .dynsym section.
	// This is used to populate the DT_MIPS_SYMTABNO entry in the .dynamic
	// section.
	dynSymCount uint64

	// gotLocalCount contains the number of local global offset table
	// entries. This is used to populate the DT_MIPS_LOCAL_GOTNO entry in
	// the .dynamic section.
	gotLocalCount uint64

	// gotSymIndex contains the index of the first dynamic symbol table
	// entry that corresponds to an entry in the global offset table.
	// This is used to populate the DT_MIPS_GOTSYM entry in the .dynamic
	// section.
	gotSymIndex uint64
)

func gentext(ctxt *ld.Link, ldr *loader.Loader) {
	if *ld.FlagD || ctxt.Target.IsExternal() {
		return
	}

	dynamic := ldr.MakeSymbolUpdater(ctxt.ArchSyms.Dynamic)

	ld.Elfwritedynent(ctxt.Arch, dynamic, elf.DT_MIPS_RLD_VERSION, 1)
	ld.Elfwritedynent(ctxt.Arch, dynamic, elf.DT_MIPS_BASE_ADDRESS, 0)

	// elfsetupplt should have been called and gotLocalCount should now
	// have its correct value.
	if gotLocalCount == 0 {
		ctxt.Errorf(0, "internal error: elfsetupplt has not been called")
	}
	ld.Elfwritedynent(ctxt.Arch, dynamic, elf.DT_MIPS_LOCAL_GOTNO, gotLocalCount)

	// DT_* entries have to exist prior to elfdynhash(), which finalises the
	// table by adding DT_NULL. However, the values for the following entries
	// are not know until after dynreloc() has completed. Add the symbols now,
	// then update their values prior to code generation.
	dts := []elf.DynTag{
		elf.DT_MIPS_SYMTABNO,
		elf.DT_MIPS_GOTSYM,
	}
	dtOffsets = make(map[elf.DynTag]int64)
	for _, dt := range dts {
		ld.Elfwritedynent(ctxt.Arch, dynamic, dt, 0)
		dtOffsets[dt] = dynamic.Size() - 8
	}
}

func adddynrel(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym, r loader.Reloc, rIdx int) bool {
	targ := r.Sym()
	var targType sym.SymKind
	if targ != 0 {
		targType = ldr.SymType(targ)
	}

	if r.Type() >= objabi.ElfRelocOffset {
		ldr.Errorf(s, "unexpected relocation type %d (%s)", r.Type(), sym.RelocName(target.Arch, r.Type()))
		return false
	}

	switch r.Type() {
	case objabi.R_CALLMIPS, objabi.R_JMPMIPS:
		if targType != sym.SDYNIMPORT {
			// Nothing to do, the relocation will be laid out in reloc
			return true
		}
		if target.IsExternal() {
			// External linker will do this relocation.
			return true
		}

		// Internal linking, build a PLT entry and change the relocation
		// target to that entry.
		if r.Add() != 0 {
			ldr.Errorf(s, "PLT call with non-zero addend (%v)", r.Add())
		}
		addpltsym(target, ldr, syms, targ)
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocSym(rIdx, syms.PLT)
		su.SetRelocAdd(rIdx, int64(ldr.SymPlt(targ)))
		return true
	}

	return false
}

func elfreloc1(ctxt *ld.Link, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, ri int, sectoff int64) bool {

	// mips64 ELF relocation (endian neutral)
	//		offset	uint64
	//		sym		uint32
	//		ssym	uint8
	//		type3	uint8
	//		type2	uint8
	//		type	uint8
	//		addend	int64

	addend := r.Xadd

	out.Write64(uint64(sectoff))

	elfsym := ld.ElfSymForReloc(ctxt, r.Xsym)
	out.Write32(uint32(elfsym))
	out.Write8(0)
	out.Write8(0)
	out.Write8(0)
	switch r.Type {
	default:
		return false
	case objabi.R_ADDR, objabi.R_DWARFSECREF:
		switch r.Size {
		case 4:
			out.Write8(uint8(elf.R_MIPS_32))
		case 8:
			out.Write8(uint8(elf.R_MIPS_64))
		default:
			return false
		}
	case objabi.R_ADDRMIPS:
		out.Write8(uint8(elf.R_MIPS_LO16))
	case objabi.R_ADDRMIPSU:
		out.Write8(uint8(elf.R_MIPS_HI16))
	case objabi.R_ADDRMIPSTLS:
		out.Write8(uint8(elf.R_MIPS_TLS_TPREL_LO16))
		if ctxt.Target.IsOpenbsd() {
			// OpenBSD mips64 does not currently offset TLS by 0x7000,
			// as such we need to add this back to get the correct offset
			// via the external linker.
			addend += 0x7000
		}
	case objabi.R_CALLMIPS,
		objabi.R_JMPMIPS:
		out.Write8(uint8(elf.R_MIPS_26))
	}
	out.Write64(uint64(addend))

	return true
}

func elfsetupplt(ctxt *ld.Link, ldr *loader.Loader, plt, gotplt *loader.SymbolBuilder, dynamic loader.Sym) {
	if plt.Size() != 0 {
		return
	}

	// Load resolver address from got[0] into r25.
	plt.AddSymRef(ctxt.Arch, gotplt.Sym(), 0, objabi.R_ADDRMIPSU, 4)
	plt.SetUint32(ctxt.Arch, plt.Size()-4, 0x3c0e0000) // lui   $14, %hi(&GOTPLT[0])
	plt.AddSymRef(ctxt.Arch, gotplt.Sym(), 0, objabi.R_ADDRMIPS, 4)
	plt.SetUint32(ctxt.Arch, plt.Size()-4, 0xddd90000) // ld    $25, %lo(&GOTPLT[0])($14)

	// Load return address into r15, the index of the got.plt entry into r24, then
	// JALR to the resolver. The address of the got.plt entry is currently in r24,
	// which we have to turn into an index.
	plt.AddSymRef(ctxt.Arch, gotplt.Sym(), 0, objabi.R_ADDRMIPS, 4)
	plt.SetUint32(ctxt.Arch, plt.Size()-4, 0x25ce0000) // addiu $14, $14, %lo(&GOTPLT[0])
	plt.AddUint32(ctxt.Arch, 0x030ec023)               // subu  $24, $24, $14
	plt.AddUint32(ctxt.Arch, 0x03e07825)               // move  $15, $31
	plt.AddUint32(ctxt.Arch, 0x0018c0c2)               // srl   $24, $24, 3
	plt.AddUint32(ctxt.Arch, 0x0320f809)               // jalr  $25
	plt.AddUint32(ctxt.Arch, 0x2718fffe)               // subu  $24, $24, 2

	if gotplt.Size() != 0 {
		ctxt.Errorf(gotplt.Sym(), "got.plt is not empty")
	}

	// Reserve got[0] for resolver address (populated by dynamic loader).
	gotplt.AddUint32(ctxt.Arch, 0)
	gotplt.AddUint32(ctxt.Arch, 0)
	gotLocalCount++

	// Reserve got[1] for ELF object pointer (populated by dynamic loader).
	gotplt.AddUint32(ctxt.Arch, 0)
	gotplt.AddUint32(ctxt.Arch, 0)
	gotLocalCount++
}

func addpltsym(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym) {
	if ldr.SymPlt(s) >= 0 {
		return
	}

	dynamic := ldr.MakeSymbolUpdater(syms.Dynamic)

	const dynSymEntrySize = 20
	if gotSymIndex == 0 {
		// Compute and update GOT symbol index.
		gotSymIndex = uint64(ldr.SymSize(syms.DynSym) / dynSymEntrySize)
		dynamic.SetUint(target.Arch, dtOffsets[elf.DT_MIPS_GOTSYM], gotSymIndex)
	}
	if dynSymCount == 0 {
		dynSymCount = uint64(ldr.SymSize(syms.DynSym) / dynSymEntrySize)
	}

	ld.Adddynsym(ldr, target, syms, s)
	dynSymCount++

	if !target.IsElf() {
		ldr.Errorf(s, "addpltsym: unsupported binary format")
	}

	plt := ldr.MakeSymbolUpdater(syms.PLT)
	gotplt := ldr.MakeSymbolUpdater(syms.GOTPLT)
	if plt.Size() == 0 {
		panic("plt is not set up")
	}

	// Load got.plt entry into r25.
	plt.AddSymRef(target.Arch, gotplt.Sym(), gotplt.Size(), objabi.R_ADDRMIPSU, 4)
	plt.SetUint32(target.Arch, plt.Size()-4, 0x3c0f0000) // lui   $15, %hi(.got.plt entry)
	plt.AddSymRef(target.Arch, gotplt.Sym(), gotplt.Size(), objabi.R_ADDRMIPS, 4)
	plt.SetUint32(target.Arch, plt.Size()-4, 0xddf90000) // ld    $25, %lo(.got.plt entry)($15)

	// Load address of got.plt entry into r24 and JALR to address in r25.
	plt.AddUint32(target.Arch, 0x03200008) // jr  $25
	plt.AddSymRef(target.Arch, gotplt.Sym(), gotplt.Size(), objabi.R_ADDRMIPS, 4)
	plt.SetUint32(target.Arch, plt.Size()-4, 0x65f80000) // daddiu $24, $15, %lo(.got.plt entry)

	// Add pointer to plt[0] to got.plt
	gotplt.AddAddrPlus(target.Arch, plt.Sym(), 0)

	ldr.SetPlt(s, int32(plt.Size()-16))

	// Update dynamic symbol count.
	dynamic.SetUint(target.Arch, dtOffsets[elf.DT_MIPS_SYMTABNO], dynSymCount)
}

func machoreloc1(*sys.Arch, *ld.OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool {
	return false
}

func archreloc(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, r loader.Reloc, s loader.Sym, val int64) (o int64, nExtReloc int, ok bool) {
	if target.IsExternal() {
		switch r.Type() {
		default:
			return val, 0, false

		case objabi.R_ADDRMIPS,
			objabi.R_ADDRMIPSU,
			objabi.R_ADDRMIPSTLS,
			objabi.R_CALLMIPS,
			objabi.R_JMPMIPS:
			return val, 1, true
		}
	}

	const isOk = true
	const noExtReloc = 0
	rs := r.Sym()
	switch r.Type() {
	case objabi.R_ADDRMIPS,
		objabi.R_ADDRMIPSU:
		t := ldr.SymValue(rs) + r.Add()
		if r.Type() == objabi.R_ADDRMIPS {
			return int64(val&0xffff0000 | t&0xffff), noExtReloc, isOk
		}
		return int64(val&0xffff0000 | ((t+1<<15)>>16)&0xffff), noExtReloc, isOk
	case objabi.R_ADDRMIPSTLS:
		// thread pointer is at 0x7000 offset from the start of TLS data area
		t := ldr.SymValue(rs) + r.Add() - 0x7000
		if target.IsOpenbsd() {
			// OpenBSD mips64 does not currently offset TLS by 0x7000,
			// as such we need to add this back to get the correct offset.
			t += 0x7000
		}
		if t < -32768 || t >= 32678 {
			ldr.Errorf(s, "TLS offset out of range %d", t)
		}
		return int64(val&0xffff0000 | t&0xffff), noExtReloc, isOk
	case objabi.R_CALLMIPS,
		objabi.R_JMPMIPS:
		// Low 26 bits = (S + A) >> 2
		t := ldr.SymValue(rs) + r.Add()
		return int64(val&0xfc000000 | (t>>2)&^0xfc000000), noExtReloc, isOk
	}

	return val, 0, false
}

func archrelocvariant(*ld.Target, *loader.Loader, loader.Reloc, sym.RelocVariant, loader.Sym, int64, []byte) int64 {
	return -1
}

func extreloc(target *ld.Target, ldr *loader.Loader, r loader.Reloc, s loader.Sym) (loader.ExtReloc, bool) {
	switch r.Type() {
	case objabi.R_ADDRMIPS,
		objabi.R_ADDRMIPSU:
		return ld.ExtrelocViaOuterSym(ldr, r, s), true

	case objabi.R_ADDRMIPSTLS,
		objabi.R_CALLMIPS,
		objabi.R_JMPMIPS:
		return ld.ExtrelocSimple(ldr, r), true
	}
	return loader.ExtReloc{}, false
}

"""



```