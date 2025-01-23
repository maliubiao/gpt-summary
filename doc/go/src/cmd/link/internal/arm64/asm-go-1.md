Response:
The user has provided the second part of a Go source code file, `asm.go`, located in `go/src/cmd/link/internal/arm64`. They want to understand its functionality. Since this is the second part, the previous part likely handled other aspects of assembly or linking for the ARM64 architecture. This part seems to focus heavily on relocations and symbol table management, specifically related to Procedure Linkage Table (PLT) and Global Offset Table (GOT) entries, as well as generating trampolines for function calls that are out of range.

Here's a breakdown of the code and how I'll approach the response:

1. **Function-by-function analysis:** I'll examine each function in this snippet and summarize its purpose.
2. **Relocation Handling:**  The core of this part seems to be `archreloc`. I'll analyze how it modifies instruction bytes based on different relocation types (`objabi.R_ARM64_GOT`, `objabi.R_ARM64_PCREL`, etc.).
3. **PLT/GOT Setup:** Functions like `elfsetupplt` and `addpltsym` deal with creating and populating the PLT and GOT, which are essential for dynamic linking.
4. **Trampolines:** The `trampoline`, `gentramp`, and `gentrampgot` functions are responsible for creating small code snippets to handle out-of-range function calls.
5. **Symbol Table Generation:** `gensymlate` focuses on creating intermediate "label" symbols to handle large address ranges in relocations, particularly relevant for external linking on Darwin and Windows.
6. **Code Examples:** I'll try to illustrate the behavior with simplified Go code examples and hypothetical inputs/outputs for the `archreloc` function.
7. **Command-line Arguments (If Applicable):** I'll check if the code directly interacts with command-line arguments (unlikely in this low-level linking code, but I'll confirm).
8. **Common Mistakes:** I'll consider if there are obvious pitfalls for developers using the *output* of this code (the linked binary).
9. **Summarize Functionality:** Finally, I'll provide a concise summary of the overall function of this code snippet.
好的，让我们来归纳一下这部分 `asm.go` 代码的功能。

这段代码主要负责 **处理 ARM64 架构下的链接过程中的重定位和符号解析，特别是与动态链接相关的部分**。  它关注如何调整指令，以便在程序加载到内存的不同位置时，代码能够正确地访问全局变量、调用外部函数等。

具体来说，这段代码的功能可以归纳为以下几点：

1. **处理不同类型的重定位 (Relocation):**  `archreloc` 函数是核心，它根据不同的重定位类型（例如 `R_ARM64_GOT`, `R_ARM64_PCREL` 等）来修改指令的二进制表示。它计算目标地址与当前指令地址的偏移，并将这些偏移值编码到指令中。

2. **支持全局偏移表 (GOT):** 代码处理 `R_ARM64_GOT` 类型的重定位，这涉及到访问全局变量。它会计算出 GOT 表中的条目地址，并将该地址的一部分或全部编码到指令中。这通常用于访问外部共享库中的全局变量。

3. **支持程序计数器相对寻址 (PCREL):** 代码处理 `R_ARM64_PCREL` 类型的重定位，这涉及到相对于当前指令地址的跳转或数据访问。它计算目标地址与当前指令地址的偏移，并将该偏移编码到指令中。

4. **处理加载/存储指令的重定位:**  对于 `R_ARM64_LDST8`, `R_ARM64_LDST16`, `R_ARM64_LDST32`, `R_ARM64_LDST64`, `R_ARM64_LDST128` 这些加载和存储指令的重定位类型，代码会计算目标地址相对于当前页面的偏移，并将偏移值编码到指令中。这通常用于访问同一页面内的局部数据。

5. **处理外部重定位 (External Relocation):** `extreloc` 函数处理需要外部链接器来完成的重定位类型，例如函数调用 (`R_CALLARM64`) 和线程局部存储 (`R_ARM64_TLS_LE`, `R_ARM64_TLS_IE`). 它会生成外部重定位记录，供链接器的后续处理。

6. **设置过程链接表 (PLT):** `elfsetupplt` 函数负责初始化 ELF 格式下的 PLT。PLT 是一种延迟绑定的机制，用于调用外部共享库中的函数。它会生成 PLT 的初始代码，用于跳转到 GOT 表中的对应条目，并触发动态链接器的解析。

7. **添加 PLT 符号:** `addpltsym` 函数用于为需要通过 PLT 调用的外部函数创建 PLT 条目和 GOT 条目。它会在 PLT 和 GOT 表中添加相应的代码和数据，并生成重定位信息。这个函数针对 ELF 和 Darwin (macOS) 两种不同的二进制格式有不同的处理方式。

8. **生成符号标签 (Symbol Labeling):** `gensymlate` 函数用于在进行外部链接时，特别是针对 Darwin 和 Windows 平台，生成额外的 "label" 符号。这是为了解决某些平台上重定位项的偏移量有限制的问题。对于超出范围的目标地址，会生成中间的标签符号，使得重定位可以指向这个中间标签，从而缩小偏移量。

9. **生成跳转桩 (Trampoline):** `trampoline`, `gentramp`, `gentrampgot` 函数用于生成跳转桩代码。当一个函数调用距离过远，无法通过直接跳转指令到达时，就会在当前代码附近生成一个小的跳转桩，先跳转到这个桩，再由桩跳转到目标函数。`gentramp` 用于普通函数调用，`gentrampgot` 用于通过 GOT 表调用的外部函数。

**总结来说，这段代码是 Go 编译器 `cmd/link` 工具中负责 ARM64 架构下目标代码重定位的关键部分，它处理了程序加载和动态链接过程中地址的调整，确保代码能够正确执行。**

由于这段代码是链接器内部实现的一部分，开发者一般不会直接调用这些函数。它的作用体现在最终生成的可执行文件或共享库中。

**易犯错的点 (开发者角度，虽然不是直接使用这段代码)：**

假设开发者在编写汇编代码或者使用了 `//go:linkname` 等机制绕过了 Go 的类型安全，手动与链接过程交互，那么可能会遇到以下易犯错的情况：

* **错误的重定位类型:**  如果手动指定了错误的重定位类型，例如对一个需要通过 GOT 表访问的全局变量使用了 PC 相対寻址，或者反之，链接器将会报错，或者程序运行时出现意想不到的错误。

* **不理解 PLT/GOT 的工作原理:**  如果在手动编写汇编代码时，没有正确设置 PLT 或 GOT 表的访问方式，会导致动态链接的符号解析失败。

* **忽略地址范围限制:**  在某些情况下，直接跳转指令的跳转范围是有限的。如果手动编写的汇编代码尝试跳转到超出范围的地址，链接器可能会报错，或者需要手动插入跳转桩。

这段代码本身的处理逻辑比较复杂，涉及到对 ARM64 指令编码的理解和各种重定位类型的细节。对于一般的 Go 开发者来说，理解其原理有助于更好地理解程序的链接过程和运行时行为，但通常不需要直接操作这些底层的细节。

### 提示词
```
这是路径为go/src/cmd/link/internal/arm64/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
case objabi.R_ARM64_GOT:
		if (val>>24)&0x9f == 0x90 {
			// R_AARCH64_ADR_GOT_PAGE
			// patch instruction: adrp
			t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
			if t >= 1<<32 || t < -1<<32 {
				ldr.Errorf(s, "program too large, address relocation distance = %d", t)
			}
			var o0 uint32
			o0 |= (uint32((t>>12)&3) << 29) | (uint32((t>>12>>2)&0x7ffff) << 5)
			return val | int64(o0), noExtReloc, isOk
		} else if val>>24 == 0xf9 {
			// R_AARCH64_LD64_GOT_LO12_NC
			// patch instruction: ldr
			t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
			if t&7 != 0 {
				ldr.Errorf(s, "invalid address: %x for relocation type: R_AARCH64_LD64_GOT_LO12_NC", t)
			}
			var o1 uint32
			o1 |= uint32(t&0xfff) << (10 - 3)
			return val | int64(uint64(o1)), noExtReloc, isOk
		} else {
			ldr.Errorf(s, "unsupported instruction for %x R_GOTARM64", val)
		}

	case objabi.R_ARM64_PCREL:
		if (val>>24)&0x9f == 0x90 {
			// R_AARCH64_ADR_PREL_PG_HI21
			// patch instruction: adrp
			t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
			if t >= 1<<32 || t < -1<<32 {
				ldr.Errorf(s, "program too large, address relocation distance = %d", t)
			}
			o0 := (uint32((t>>12)&3) << 29) | (uint32((t>>12>>2)&0x7ffff) << 5)
			return val | int64(o0), noExtReloc, isOk
		} else if (val>>24)&0x9f == 0x91 {
			// ELF R_AARCH64_ADD_ABS_LO12_NC or Mach-O ARM64_RELOC_PAGEOFF12
			// patch instruction: add
			t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
			o1 := uint32(t&0xfff) << 10
			return val | int64(o1), noExtReloc, isOk
		} else if (val>>24)&0x3b == 0x39 {
			// Mach-O ARM64_RELOC_PAGEOFF12
			// patch ldr/str(b/h/w/d/q) (integer or vector) instructions, which have different scaling factors.
			// Mach-O uses same relocation type for them.
			shift := uint32(val) >> 30
			if shift == 0 && (val>>20)&0x048 == 0x048 { // 128-bit vector load
				shift = 4
			}
			t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
			if t&(1<<shift-1) != 0 {
				ldr.Errorf(s, "invalid address: %x for relocation type: ARM64_RELOC_PAGEOFF12", t)
			}
			o1 := (uint32(t&0xfff) >> shift) << 10
			return val | int64(o1), noExtReloc, isOk
		} else {
			ldr.Errorf(s, "unsupported instruction for %x R_ARM64_PCREL", val)
		}

	case objabi.R_ARM64_LDST8:
		t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
		o0 := uint32(t&0xfff) << 10
		return val | int64(o0), noExtReloc, true

	case objabi.R_ARM64_LDST16:
		t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
		if t&1 != 0 {
			ldr.Errorf(s, "invalid address: %x for relocation type: R_AARCH64_LDST16_ABS_LO12_NC", t)
		}
		o0 := (uint32(t&0xfff) >> 1) << 10
		return val | int64(o0), noExtReloc, true

	case objabi.R_ARM64_LDST32:
		t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
		if t&3 != 0 {
			ldr.Errorf(s, "invalid address: %x for relocation type: R_AARCH64_LDST32_ABS_LO12_NC", t)
		}
		o0 := (uint32(t&0xfff) >> 2) << 10
		return val | int64(o0), noExtReloc, true

	case objabi.R_ARM64_LDST64:
		t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
		if t&7 != 0 {
			ldr.Errorf(s, "invalid address: %x for relocation type: R_AARCH64_LDST64_ABS_LO12_NC", t)
		}
		o0 := (uint32(t&0xfff) >> 3) << 10
		return val | int64(o0), noExtReloc, true

	case objabi.R_ARM64_LDST128:
		t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
		if t&15 != 0 {
			ldr.Errorf(s, "invalid address: %x for relocation type: R_AARCH64_LDST128_ABS_LO12_NC", t)
		}
		o0 := (uint32(t&0xfff) >> 4) << 10
		return val | int64(o0), noExtReloc, true
	}

	return val, 0, false
}

func archrelocvariant(*ld.Target, *loader.Loader, loader.Reloc, sym.RelocVariant, loader.Sym, int64, []byte) int64 {
	log.Fatalf("unexpected relocation variant")
	return -1
}

func extreloc(target *ld.Target, ldr *loader.Loader, r loader.Reloc, s loader.Sym) (loader.ExtReloc, bool) {
	switch rt := r.Type(); rt {
	case objabi.R_ARM64_GOTPCREL,
		objabi.R_ARM64_PCREL_LDST8,
		objabi.R_ARM64_PCREL_LDST16,
		objabi.R_ARM64_PCREL_LDST32,
		objabi.R_ARM64_PCREL_LDST64,
		objabi.R_ADDRARM64:
		rr := ld.ExtrelocViaOuterSym(ldr, r, s)
		return rr, true
	case objabi.R_CALLARM64,
		objabi.R_ARM64_TLS_LE,
		objabi.R_ARM64_TLS_IE:
		return ld.ExtrelocSimple(ldr, r), true
	}
	return loader.ExtReloc{}, false
}

func elfsetupplt(ctxt *ld.Link, ldr *loader.Loader, plt, gotplt *loader.SymbolBuilder, dynamic loader.Sym) {
	if plt.Size() == 0 {
		// stp     x16, x30, [sp, #-16]!
		// identifying information
		plt.AddUint32(ctxt.Arch, 0xa9bf7bf0)

		// the following two instructions (adrp + ldr) load *got[2] into x17
		// adrp    x16, &got[0]
		plt.AddSymRef(ctxt.Arch, gotplt.Sym(), 16, objabi.R_ARM64_GOT, 4)
		plt.SetUint32(ctxt.Arch, plt.Size()-4, 0x90000010)

		// <imm> is the offset value of &got[2] to &got[0], the same below
		// ldr     x17, [x16, <imm>]
		plt.AddSymRef(ctxt.Arch, gotplt.Sym(), 16, objabi.R_ARM64_GOT, 4)
		plt.SetUint32(ctxt.Arch, plt.Size()-4, 0xf9400211)

		// add     x16, x16, <imm>
		plt.AddSymRef(ctxt.Arch, gotplt.Sym(), 16, objabi.R_ARM64_PCREL, 4)
		plt.SetUint32(ctxt.Arch, plt.Size()-4, 0x91000210)

		// br      x17
		plt.AddUint32(ctxt.Arch, 0xd61f0220)

		// 3 nop for place holder
		plt.AddUint32(ctxt.Arch, 0xd503201f)
		plt.AddUint32(ctxt.Arch, 0xd503201f)
		plt.AddUint32(ctxt.Arch, 0xd503201f)

		// check gotplt.size == 0
		if gotplt.Size() != 0 {
			ctxt.Errorf(gotplt.Sym(), "got.plt is not empty at the very beginning")
		}
		gotplt.AddAddrPlus(ctxt.Arch, dynamic, 0)

		gotplt.AddUint64(ctxt.Arch, 0)
		gotplt.AddUint64(ctxt.Arch, 0)
	}
}

func addpltsym(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym) {
	if ldr.SymPlt(s) >= 0 {
		return
	}

	ld.Adddynsym(ldr, target, syms, s)

	if target.IsElf() {
		plt := ldr.MakeSymbolUpdater(syms.PLT)
		gotplt := ldr.MakeSymbolUpdater(syms.GOTPLT)
		rela := ldr.MakeSymbolUpdater(syms.RelaPLT)
		if plt.Size() == 0 {
			panic("plt is not set up")
		}

		// adrp    x16, &got.plt[0]
		plt.AddAddrPlus4(target.Arch, gotplt.Sym(), gotplt.Size())
		plt.SetUint32(target.Arch, plt.Size()-4, 0x90000010)
		relocs := plt.Relocs()
		plt.SetRelocType(relocs.Count()-1, objabi.R_ARM64_GOT)

		// <offset> is the offset value of &got.plt[n] to &got.plt[0]
		// ldr     x17, [x16, <offset>]
		plt.AddAddrPlus4(target.Arch, gotplt.Sym(), gotplt.Size())
		plt.SetUint32(target.Arch, plt.Size()-4, 0xf9400211)
		relocs = plt.Relocs()
		plt.SetRelocType(relocs.Count()-1, objabi.R_ARM64_GOT)

		// add     x16, x16, <offset>
		plt.AddAddrPlus4(target.Arch, gotplt.Sym(), gotplt.Size())
		plt.SetUint32(target.Arch, plt.Size()-4, 0x91000210)
		relocs = plt.Relocs()
		plt.SetRelocType(relocs.Count()-1, objabi.R_ARM64_PCREL)

		// br      x17
		plt.AddUint32(target.Arch, 0xd61f0220)

		// add to got.plt: pointer to plt[0]
		gotplt.AddAddrPlus(target.Arch, plt.Sym(), 0)

		// rela
		rela.AddAddrPlus(target.Arch, gotplt.Sym(), gotplt.Size()-8)
		sDynid := ldr.SymDynid(s)

		rela.AddUint64(target.Arch, elf.R_INFO(uint32(sDynid), uint32(elf.R_AARCH64_JUMP_SLOT)))
		rela.AddUint64(target.Arch, 0)

		ldr.SetPlt(s, int32(plt.Size()-16))
	} else if target.IsDarwin() {
		ld.AddGotSym(target, ldr, syms, s, 0)

		sDynid := ldr.SymDynid(s)
		lep := ldr.MakeSymbolUpdater(syms.LinkEditPLT)
		lep.AddUint32(target.Arch, uint32(sDynid))

		plt := ldr.MakeSymbolUpdater(syms.PLT)
		ldr.SetPlt(s, int32(plt.Size()))

		// adrp x16, GOT
		plt.AddUint32(target.Arch, 0x90000010)
		r, _ := plt.AddRel(objabi.R_ARM64_GOT)
		r.SetOff(int32(plt.Size() - 4))
		r.SetSiz(4)
		r.SetSym(syms.GOT)
		r.SetAdd(int64(ldr.SymGot(s)))

		// ldr x17, [x16, <offset>]
		plt.AddUint32(target.Arch, 0xf9400211)
		r, _ = plt.AddRel(objabi.R_ARM64_GOT)
		r.SetOff(int32(plt.Size() - 4))
		r.SetSiz(4)
		r.SetSym(syms.GOT)
		r.SetAdd(int64(ldr.SymGot(s)))

		// br x17
		plt.AddUint32(target.Arch, 0xd61f0220)
	} else {
		ldr.Errorf(s, "addpltsym: unsupported binary format")
	}
}

const (
	machoRelocLimit = 1 << 23
	peRelocLimit    = 1 << 20
)

func gensymlate(ctxt *ld.Link, ldr *loader.Loader) {
	// When external linking on darwin, Mach-O relocation has only signed 24-bit
	// addend. For large symbols, we generate "label" symbols in the middle, so
	// that relocations can target them with smaller addends.
	// On Windows, we only get 21 bits, again (presumably) signed.
	// Also, on Windows (always) and Darwin (for very large binaries), the external
	// linker doesn't support CALL relocations with addend, so we generate "label"
	// symbols for functions of which we can target the middle (Duff's devices).
	if !ctxt.IsDarwin() && !ctxt.IsWindows() || !ctxt.IsExternal() {
		return
	}

	limit := int64(machoRelocLimit)
	if ctxt.IsWindows() {
		limit = peRelocLimit
	}

	// addLabelSyms adds "label" symbols at s+limit, s+2*limit, etc.
	addLabelSyms := func(s loader.Sym, limit, sz int64) {
		v := ldr.SymValue(s)
		for off := limit; off < sz; off += limit {
			p := ldr.LookupOrCreateSym(offsetLabelName(ldr, s, off), ldr.SymVersion(s))
			ldr.SetAttrReachable(p, true)
			ldr.SetSymValue(p, v+off)
			ldr.SetSymSect(p, ldr.SymSect(s))
			if ctxt.IsDarwin() {
				ld.AddMachoSym(ldr, p)
			} else if ctxt.IsWindows() {
				ld.AddPELabelSym(ldr, p)
			} else {
				panic("missing case in gensymlate")
			}
			// fmt.Printf("gensymlate %s %x\n", ldr.SymName(p), ldr.SymValue(p))
		}
	}

	// Generate symbol names for every offset we need in duffcopy/duffzero (only 64 each).
	if s := ldr.Lookup("runtime.duffcopy", sym.SymVerABIInternal); s != 0 && ldr.AttrReachable(s) {
		addLabelSyms(s, 8, 8*64)
	}
	if s := ldr.Lookup("runtime.duffzero", sym.SymVerABIInternal); s != 0 && ldr.AttrReachable(s) {
		addLabelSyms(s, 4, 4*64)
	}

	if ctxt.IsDarwin() {
		big := false
		for _, seg := range ld.Segments {
			if seg.Length >= machoRelocLimit {
				big = true
				break
			}
		}
		if !big {
			return // skip work if nothing big
		}
	}

	for s, n := loader.Sym(1), loader.Sym(ldr.NSym()); s < n; s++ {
		if !ldr.AttrReachable(s) {
			continue
		}
		t := ldr.SymType(s)
		if t.IsText() {
			// Except for Duff's devices (handled above), we don't
			// target the middle of a function.
			continue
		}
		if t >= sym.SDWARFSECT {
			continue // no need to add label for DWARF symbols
		}
		sz := ldr.SymSize(s)
		if sz <= limit {
			continue
		}
		addLabelSyms(s, limit, sz)
	}

	// Also for carrier symbols (for which SymSize is 0)
	for _, ss := range ld.CarrierSymByType {
		if ss.Sym != 0 && ss.Size > limit {
			addLabelSyms(ss.Sym, limit, ss.Size)
		}
	}
}

// offsetLabelName returns the name of the "label" symbol used for a
// relocation targeting s+off. The label symbols is used on Darwin/Windows
// when external linking, so that the addend fits in a Mach-O/PE relocation.
func offsetLabelName(ldr *loader.Loader, s loader.Sym, off int64) string {
	if off>>20<<20 == off {
		return fmt.Sprintf("%s+%dMB", ldr.SymExtname(s), off>>20)
	}
	return fmt.Sprintf("%s+%d", ldr.SymExtname(s), off)
}

// Convert the direct jump relocation r to refer to a trampoline if the target is too far.
func trampoline(ctxt *ld.Link, ldr *loader.Loader, ri int, rs, s loader.Sym) {
	relocs := ldr.Relocs(s)
	r := relocs.At(ri)
	const pcrel = 1
	switch r.Type() {
	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_CALL26),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_JUMP26),
		objabi.MachoRelocOffset + ld.MACHO_ARM64_RELOC_BRANCH26*2 + pcrel:
		// Host object relocations that will be turned into a PLT call.
		// The PLT may be too far. Insert a trampoline for them.
		fallthrough
	case objabi.R_CALLARM64:
		var t int64
		// ldr.SymValue(rs) == 0 indicates a cross-package jump to a function that is not yet
		// laid out. Conservatively use a trampoline. This should be rare, as we lay out packages
		// in dependency order.
		if ldr.SymValue(rs) != 0 {
			t = ldr.SymValue(rs) + r.Add() - (ldr.SymValue(s) + int64(r.Off()))
		}
		if t >= 1<<27 || t < -1<<27 || ldr.SymValue(rs) == 0 || (*ld.FlagDebugTramp > 1 && (ldr.SymPkg(s) == "" || ldr.SymPkg(s) != ldr.SymPkg(rs))) {
			// direct call too far, need to insert trampoline.
			// look up existing trampolines first. if we found one within the range
			// of direct call, we can reuse it. otherwise create a new one.
			var tramp loader.Sym
			for i := 0; ; i++ {
				oName := ldr.SymName(rs)
				name := oName + fmt.Sprintf("%+x-tramp%d", r.Add(), i)
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

				t = ldr.SymValue(tramp) - (ldr.SymValue(s) + int64(r.Off()))
				if t >= -1<<27 && t < 1<<27 {
					// found an existing trampoline that is not too far
					// we can just use it
					break
				}
			}
			if ldr.SymType(tramp) == 0 {
				// trampoline does not exist, create one
				trampb := ldr.MakeSymbolUpdater(tramp)
				ctxt.AddTramp(trampb, ldr.SymType(s))
				if ldr.SymType(rs) == sym.SDYNIMPORT {
					if r.Add() != 0 {
						ctxt.Errorf(s, "nonzero addend for DYNIMPORT call: %v+%d", ldr.SymName(rs), r.Add())
					}
					gentrampgot(ctxt, ldr, trampb, rs)
				} else {
					gentramp(ctxt, ldr, trampb, rs, r.Add())
				}
			}
			// modify reloc to point to tramp, which will be resolved later
			sb := ldr.MakeSymbolUpdater(s)
			relocs := sb.Relocs()
			r := relocs.At(ri)
			r.SetSym(tramp)
			r.SetAdd(0) // clear the offset embedded in the instruction
		}
	default:
		ctxt.Errorf(s, "trampoline called with non-jump reloc: %d (%s)", r.Type(), sym.RelocName(ctxt.Arch, r.Type()))
	}
}

// generate a trampoline to target+offset.
func gentramp(ctxt *ld.Link, ldr *loader.Loader, tramp *loader.SymbolBuilder, target loader.Sym, offset int64) {
	tramp.SetSize(12) // 3 instructions
	P := make([]byte, tramp.Size())
	o1 := uint32(0x90000010) // adrp x16, target
	o2 := uint32(0x91000210) // add x16, pc-relative-offset
	o3 := uint32(0xd61f0200) // br x16
	ctxt.Arch.ByteOrder.PutUint32(P, o1)
	ctxt.Arch.ByteOrder.PutUint32(P[4:], o2)
	ctxt.Arch.ByteOrder.PutUint32(P[8:], o3)
	tramp.SetData(P)

	r, _ := tramp.AddRel(objabi.R_ADDRARM64)
	r.SetSiz(8)
	r.SetSym(target)
	r.SetAdd(offset)
}

// generate a trampoline to target+offset for a DYNIMPORT symbol via GOT.
func gentrampgot(ctxt *ld.Link, ldr *loader.Loader, tramp *loader.SymbolBuilder, target loader.Sym) {
	tramp.SetSize(12) // 3 instructions
	P := make([]byte, tramp.Size())
	o1 := uint32(0x90000010) // adrp x16, target@GOT
	o2 := uint32(0xf9400210) // ldr x16, [x16, offset]
	o3 := uint32(0xd61f0200) // br x16
	ctxt.Arch.ByteOrder.PutUint32(P, o1)
	ctxt.Arch.ByteOrder.PutUint32(P[4:], o2)
	ctxt.Arch.ByteOrder.PutUint32(P[8:], o3)
	tramp.SetData(P)

	r, _ := tramp.AddRel(objabi.R_ARM64_GOTPCREL)
	r.SetSiz(8)
	r.SetSym(target)
}
```