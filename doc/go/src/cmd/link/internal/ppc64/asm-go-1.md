Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the PowerPC64 architecture-specific assembler in the Go linker.

To achieve this, I will:
1. **Identify the main functions:** Look for top-level function declarations.
2. **Analyze each function's purpose:** Understand what each function does based on its name, parameters, and logic.
3. **Group related functions:** Identify functions that work together to achieve a specific task.
4. **Summarize the overall functionality:**  Combine the individual function summaries into a cohesive description of the code's role in the linking process for the PowerPC64 architecture.

Based on the provided code, the main functions are:
- `canUseRel`:  Determines if a relocation can be handled.
- `xcoffreloc1`: Handles XCOFF-specific relocation.
- `elfreloc1`: Handles ELF-specific relocation.
- `elfsetupplt`: Sets up the Procedure Linkage Table (PLT) for ELF.
- `machoreloc1`: Handles Mach-O-specific relocation (currently does nothing).
- `symtoc`:  Gets the Table of Contents (TOC) value for a symbol.
- `archreloctoc`:  Relocates TOC-relative symbols.
- `archrelocaddr`: Relocates symbol addresses.
- `r2Valid`: Checks if the TOC register (R2) is valid.
- `isLinkingPIC`: Checks if the linking is for position-independent code.
- `trampoline`:  Handles long jumps by creating trampolines.
- `gentramp`: Generates trampoline code.
- `unpackInstPair`: Unpacks a pair of instructions from a 64-bit value.
- `packInstPair`: Packs a pair of instructions into a 64-bit value.
- `computeHA`, `computeLO`, `computePrefix34HI`: Helper functions to compute parts of instruction words.
- `computeTLSLEReloc`: Computes the offset for Thread Local Storage (TLS) relocations.
- `archreloc`:  The main function for architecture-specific relocation.
- `archrelocvariant`: Handles relocation variants.
- `extreloc`: Creates external relocation entries.
- `addpltsym`: Adds a symbol to the PLT.
- `ensureglinkresolver`: Ensures the `.glink` resolver stub exists and returns it.

These functions appear to be involved in:
- **Relocation processing:** Handling different relocation types for different object file formats (ELF, XCOFF).
- **TOC management:** Dealing with TOC-relative addressing on PowerPC64.
- **Trampoline generation:** Creating code snippets to handle long jumps.
- **TLS relocation:** Handling relocations related to thread-local storage.
- **PLT setup:** Setting up the PLT for dynamic linking.
- **`.glink` resolver:** Managing a special resolver for global linkage.
这段代码是 Go 语言链接器（`go link`）中用于处理 PowerPC64 架构的汇编代码部分。它是 `go/src/cmd/link/internal/ppc64/asm.go` 文件的后半部分，主要负责**完成与代码重定位相关的任务**。

具体来说，它的功能可以归纳为以下几点：

1. **处理不同目标文件格式的重定位:**
   - 针对 ELF (Executable and Linkable Format) 格式的目标文件，提供了 `elfreloc1` 和 `elfsetupplt` 函数，用于处理 ELF 格式特定的重定位类型，以及设置过程链接表 (PLT)。
   - 针对 XCOFF (Extended Common Object File Format) 格式的目标文件，提供了 `xcoffreloc1` 函数来处理 XCOFF 格式的重定位。
   - 针对 Mach-O 格式的目标文件，提供了 `machoreloc1` 函数，但目前该函数返回 `false`，表示尚未实现或不需要处理 Mach-O 的重定位。

2. **处理 TOC (Table of Contents) 相关的重定位:**
   - 提供了 `symtoc` 函数来获取符号的 TOC 值。
   - 提供了 `archreloctoc` 函数来处理针对 TOC 相对地址的重定位。这在 PowerPC64 架构中，为了高效访问全局数据，经常会使用相对于 TOC 的偏移量。

3. **处理一般的地址重定位:**
   - 提供了 `archrelocaddr` 函数来处理一般的符号地址重定位。

4. **处理函数调用跳转相关的重定位和生成跳转桩 (Trampoline):**
   - `trampoline` 函数负责判断是否需要为函数调用创建一个跳转桩。当目标地址距离当前指令太远，无法直接用一条跳转指令到达时，链接器会插入一个跳转桩，先跳转到跳转桩，再从跳转桩跳转到目标地址。
   - `gentramp` 函数负责生成跳转桩的代码。生成的跳转桩代码会加载目标地址到寄存器，然后执行间接跳转。

5. **辅助函数:**
   - `r2Valid` 函数判断 TOC 寄存器 (R2) 是否有效，这与是否是位置无关代码 (PIC) 有关。
   - `isLinkingPIC` 函数判断当前是否正在链接位置无关的代码。
   - `unpackInstPair` 和 `packInstPair` 函数用于将 64 位的值拆分和组合成一对 32 位的指令字，以处理指令级别的重定位。
   - `computeHA`, `computeLO`, `computePrefix34HI` 等函数用于计算指令中特定字段的值，例如高位调整值 (High-Adjusted)、低位值等。
   - `computeTLSLEReloc` 函数用于计算线程局部存储 (TLS) 相关的重定位偏移量。

6. **主要的重定位处理函数 `archreloc`:**
   - 这是 PowerPC64 架构的核心重定位处理函数。它根据不同的重定位类型，调用相应的处理逻辑（例如 `archreloctoc` 或 `archrelocaddr`），并对指令进行修改，使其指向正确的地址。
   - 它还会处理外部链接的情况，决定是否需要生成外部重定位项。

7. **处理重定位的变体 (`archrelocvariant`):**
   - 允许对重定位的值进行进一步的修改，例如提取低位、高位等，并进行溢出检查。

8. **创建外部重定位项 (`extreloc`):**
   -  当需要将重定位信息传递给外部链接器时，此函数会创建相应的外部重定位项。

9. **添加 PLT 符号 (`addpltsym`):**
   -  负责将需要通过 PLT 进行动态链接的符号添加到 PLT 表中。

10. **生成 `.glink` 解析器桩 (`ensureglinkresolver`):**
    -  为动态链接生成一个特殊的解析器桩，用于在运行时解析动态链接的符号。

**功能归纳：**

总而言之，这段代码是 Go 语言链接器中 **PowerPC64 架构特有的重定位处理模块**。它的主要任务是根据不同的目标文件格式和重定位类型，**计算并应用重定位信息，修正代码中的地址引用，确保程序在加载和运行时能够正确地访问代码和数据**。 它还负责处理与 TOC、跳转桩以及动态链接相关的特定需求。

由于这是一个代码片段，无法直接运行，以下用一些简化的 Go 代码示例来说明其功能概念。

**示例 1:  `archrelocaddr` 的简化概念**

假设我们有以下 PowerPC64 汇编指令，需要进行地址重定位：

```assembly
  lis r3, #high_address  // 加载高位地址
  ori r3, r3, #low_address   // 加载低位地址
```

`archrelocaddr` 的作用就是根据符号 `target_symbol` 的实际地址，计算出 `high_address` 和 `low_address` 应该填入的值。

```go
// 假设的输入
targetSymbolAddress := uint64(0x123456789ABCDEF0)
instructionWord1 := uint32(0x3c600000) // lis r3, #high_address
instructionWord2 := uint32(0x60630000) // ori r3, r3, #low_address

// 假设的 archrelocaddr 的简化版本
func simplifiedArchRelocAddr(targetAddress uint64, inst1 uint32, inst2 uint32) (uint32, uint32) {
	high := uint32((targetAddress >> 16) & 0xFFFF)
	low := uint32(targetAddress & 0xFFFF)

	inst1 |= high // 将高位地址填入 lis 指令
	inst2 |= low  // 将低位地址填入 ori 指令
	return inst1, inst2
}

// 调用
newInst1, newInst2 := simplifiedArchRelocAddr(targetSymbolAddress, instructionWord1, instructionWord2)

// 假设的输出
// newInst1 应该包含计算出的高位地址
// newInst2 应该包含计算出的低位地址
println(fmt.Sprintf("New Instruction 1: 0x%X", newInst1))
println(fmt.Sprintf("New Instruction 2: 0x%X", newInst2))
```

**示例 2: `trampoline` 的简化概念**

假设有一个函数调用指令，目标地址太远，需要生成跳转桩：

```assembly
  b target_function  // 直接跳转到 target_function (距离可能过远)
```

`trampoline` 的作用是生成一个中间的跳转桩，并将原始的跳转指令修改为跳转到跳转桩。

```go
// 假设需要跳转的目标函数地址
targetFunctionAddress := uint64(0xAABBCCDD00112233)

// 假设的生成跳转桩的函数 (简化版)
func generateTrampoline(targetAddress uint64) []byte {
	// 生成加载目标地址到寄存器的指令 (例如 r12)
	loadAddressInstruction := []byte{ /* 加载指令的字节码 */ }

	// 生成跳转到寄存器的指令
	jumpInstruction := []byte{ /* 跳转指令的字节码 */ }

	return append(loadAddressInstruction, jumpInstruction...)
}

// 生成跳转桩
trampolineCode := generateTrampoline(targetFunctionAddress)

// 假设的修改原始跳转指令，使其跳转到跳转桩的起始地址
trampolineStartAddress := uint64(0xFFFF0000) // 假设跳转桩的起始地址
// ... 修改原始指令的逻辑 ...

println(fmt.Sprintf("Trampoline Code: %X", trampolineCode))
println(fmt.Sprintf("Original jump instruction now jumps to: 0x%X", trampolineStartAddress))
```

**易犯错的点：**

这段代码主要由链接器的开发者维护，普通 Go 语言使用者通常不会直接接触。 开发者在编写链接器代码时，容易犯错的点可能包括：

* **重定位类型的理解错误：** PowerPC64 架构有多种重定位类型，每种类型对应不同的计算方式和应用场景。理解错误会导致重定位计算错误。
* **指令格式和编码的错误：**  PowerPC64 指令格式复杂，操作码、寄存器、立即数等字段的位置和编码方式需要精确把握。
* **TOC 相关的处理错误：** TOC 的管理和使用需要遵循特定的约定，错误的处理可能导致程序运行时访问到错误的数据。
* **跳转桩的生成和管理错误：** 跳转桩的生成时机、代码生成以及与原始跳转指令的连接都需要仔细处理。
* **字节序 (Endianness) 的处理：** PowerPC64 可以配置为大端或小端模式，链接器代码需要正确处理字节序问题。

由于代码没有涉及到具体的命令行参数处理，因此无法详细介绍。 这是一个代码片段，上下文是 Go 链接器的内部实现，通常不涉及直接的命令行参数处理，链接器的参数由 `go build` 或 `go link` 命令传递。

### 提示词
```
这是路径为go/src/cmd/link/internal/ppc64/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
. Instead we delay it
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
		// Generate R_PPC64_RELATIVE relocations for best
		// efficiency in the dynamic linker.
		//
		// As noted above, symbol addresses have not been
		// assigned yet, so we can't generate the final reloc
		// entry yet. We ultimately want:
		//
		// r_offset = s + r.Off
		// r_info = R_PPC64_RELATIVE
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
			rela.AddUint64(target.Arch, elf.R_INFO(0, uint32(elf.R_PPC64_RELATIVE)))
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

	return false
}

func xcoffreloc1(arch *sys.Arch, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, sectoff int64) bool {
	rs := r.Xsym

	emitReloc := func(v uint16, off uint64) {
		out.Write64(uint64(sectoff) + off)
		out.Write32(uint32(ldr.SymDynid(rs)))
		out.Write16(v)
	}

	var v uint16
	switch r.Type {
	default:
		return false
	case objabi.R_ADDR, objabi.R_DWARFSECREF:
		v = ld.XCOFF_R_POS
		if r.Size == 4 {
			v |= 0x1F << 8
		} else {
			v |= 0x3F << 8
		}
		emitReloc(v, 0)
	case objabi.R_ADDRPOWER_TOCREL:
	case objabi.R_ADDRPOWER_TOCREL_DS:
		emitReloc(ld.XCOFF_R_TOCU|(0x0F<<8), 2)
		emitReloc(ld.XCOFF_R_TOCL|(0x0F<<8), 6)
	case objabi.R_POWER_TLS_LE:
		// This only supports 16b relocations.  It is fixed up in archreloc.
		emitReloc(ld.XCOFF_R_TLS_LE|0x0F<<8, 2)
	case objabi.R_CALLPOWER:
		if r.Size != 4 {
			return false
		}
		emitReloc(ld.XCOFF_R_RBR|0x19<<8, 0)
	case objabi.R_XCOFFREF:
		emitReloc(ld.XCOFF_R_REF|0x3F<<8, 0)
	}
	return true
}

func elfreloc1(ctxt *ld.Link, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, ri int, sectoff int64) bool {
	// Beware that bit0~bit15 start from the third byte of an instruction in Big-Endian machines.
	rt := r.Type
	if rt == objabi.R_ADDR || rt == objabi.R_POWER_TLS || rt == objabi.R_CALLPOWER || rt == objabi.R_DWARFSECREF {
	} else {
		if ctxt.Arch.ByteOrder == binary.BigEndian {
			sectoff += 2
		}
	}
	out.Write64(uint64(sectoff))

	elfsym := ld.ElfSymForReloc(ctxt, r.Xsym)
	switch rt {
	default:
		return false
	case objabi.R_ADDR, objabi.R_DWARFSECREF:
		switch r.Size {
		case 4:
			out.Write64(uint64(elf.R_PPC64_ADDR32) | uint64(elfsym)<<32)
		case 8:
			out.Write64(uint64(elf.R_PPC64_ADDR64) | uint64(elfsym)<<32)
		default:
			return false
		}
	case objabi.R_ADDRPOWER_D34:
		out.Write64(uint64(elf.R_PPC64_D34) | uint64(elfsym)<<32)
	case objabi.R_ADDRPOWER_PCREL34:
		out.Write64(uint64(elf.R_PPC64_PCREL34) | uint64(elfsym)<<32)
	case objabi.R_POWER_TLS:
		out.Write64(uint64(elf.R_PPC64_TLS) | uint64(elfsym)<<32)
	case objabi.R_POWER_TLS_LE:
		out.Write64(uint64(elf.R_PPC64_TPREL16_HA) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_PPC64_TPREL16_LO) | uint64(elfsym)<<32)
	case objabi.R_POWER_TLS_LE_TPREL34:
		out.Write64(uint64(elf.R_PPC64_TPREL34) | uint64(elfsym)<<32)
	case objabi.R_POWER_TLS_IE_PCREL34:
		out.Write64(uint64(elf.R_PPC64_GOT_TPREL_PCREL34) | uint64(elfsym)<<32)
	case objabi.R_POWER_TLS_IE:
		out.Write64(uint64(elf.R_PPC64_GOT_TPREL16_HA) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_PPC64_GOT_TPREL16_LO_DS) | uint64(elfsym)<<32)
	case objabi.R_ADDRPOWER:
		out.Write64(uint64(elf.R_PPC64_ADDR16_HA) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_PPC64_ADDR16_LO) | uint64(elfsym)<<32)
	case objabi.R_ADDRPOWER_DS:
		out.Write64(uint64(elf.R_PPC64_ADDR16_HA) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_PPC64_ADDR16_LO_DS) | uint64(elfsym)<<32)
	case objabi.R_ADDRPOWER_GOT:
		out.Write64(uint64(elf.R_PPC64_GOT16_HA) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_PPC64_GOT16_LO_DS) | uint64(elfsym)<<32)
	case objabi.R_ADDRPOWER_GOT_PCREL34:
		out.Write64(uint64(elf.R_PPC64_GOT_PCREL34) | uint64(elfsym)<<32)
	case objabi.R_ADDRPOWER_PCREL:
		out.Write64(uint64(elf.R_PPC64_REL16_HA) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_PPC64_REL16_LO) | uint64(elfsym)<<32)
		r.Xadd += 4
	case objabi.R_ADDRPOWER_TOCREL:
		out.Write64(uint64(elf.R_PPC64_TOC16_HA) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_PPC64_TOC16_LO) | uint64(elfsym)<<32)
	case objabi.R_ADDRPOWER_TOCREL_DS:
		out.Write64(uint64(elf.R_PPC64_TOC16_HA) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_PPC64_TOC16_LO_DS) | uint64(elfsym)<<32)
	case objabi.R_CALLPOWER:
		if r.Size != 4 {
			return false
		}
		if !hasPCrel {
			out.Write64(uint64(elf.R_PPC64_REL24) | uint64(elfsym)<<32)
		} else {
			// TOC is not used in PCrel compiled Go code.
			out.Write64(uint64(elf.R_PPC64_REL24_NOTOC) | uint64(elfsym)<<32)
		}

	}
	out.Write64(uint64(r.Xadd))

	return true
}

func elfsetupplt(ctxt *ld.Link, ldr *loader.Loader, plt, got *loader.SymbolBuilder, dynamic loader.Sym) {
	if plt.Size() == 0 {
		// The dynamic linker stores the address of the
		// dynamic resolver and the DSO identifier in the two
		// doublewords at the beginning of the .plt section
		// before the PLT array. Reserve space for these.
		plt.SetSize(16)
	}
}

func machoreloc1(*sys.Arch, *ld.OutBuf, *loader.Loader, loader.Sym, loader.ExtReloc, int64) bool {
	return false
}

// Return the value of .TOC. for symbol s
func symtoc(ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym) int64 {
	v := ldr.SymVersion(s)
	if out := ldr.OuterSym(s); out != 0 {
		v = ldr.SymVersion(out)
	}

	toc := syms.DotTOC[v]
	if toc == 0 {
		ldr.Errorf(s, "TOC-relative relocation in object without .TOC.")
		return 0
	}

	return ldr.SymValue(toc)
}

// archreloctoc relocates a TOC relative symbol.
func archreloctoc(ldr *loader.Loader, target *ld.Target, syms *ld.ArchSyms, r loader.Reloc, s loader.Sym, val int64) int64 {
	rs := r.Sym()
	var o1, o2 uint32
	var t int64
	useAddi := false

	if target.IsBigEndian() {
		o1 = uint32(val >> 32)
		o2 = uint32(val)
	} else {
		o1 = uint32(val)
		o2 = uint32(val >> 32)
	}

	// On AIX, TOC data accesses are always made indirectly against R2 (a sequence of addis+ld+load/store). If the
	// The target of the load is known, the sequence can be written into addis+addi+load/store. On Linux,
	// TOC data accesses are always made directly against R2 (e.g addis+load/store).
	if target.IsAIX() {
		if !strings.HasPrefix(ldr.SymName(rs), "TOC.") {
			ldr.Errorf(s, "archreloctoc called for a symbol without TOC anchor")
		}
		relocs := ldr.Relocs(rs)
		tarSym := relocs.At(0).Sym()

		if target.IsInternal() && tarSym != 0 && ldr.AttrReachable(tarSym) && ldr.SymSect(tarSym).Seg == &ld.Segdata {
			t = ldr.SymValue(tarSym) + r.Add() - ldr.SymValue(syms.TOC)
			// change ld to addi in the second instruction
			o2 = (o2 & 0x03FF0000) | 0xE<<26
			useAddi = true
		} else {
			t = ldr.SymValue(rs) + r.Add() - ldr.SymValue(syms.TOC)
		}
	} else {
		t = ldr.SymValue(rs) + r.Add() - symtoc(ldr, syms, s)
	}

	if t != int64(int32(t)) {
		ldr.Errorf(s, "TOC relocation for %s is too big to relocate %s: 0x%x", ldr.SymName(s), rs, t)
	}

	if t&0x8000 != 0 {
		t += 0x10000
	}

	o1 |= uint32((t >> 16) & 0xFFFF)

	switch r.Type() {
	case objabi.R_ADDRPOWER_TOCREL_DS:
		if useAddi {
			o2 |= uint32(t) & 0xFFFF
		} else {
			if t&3 != 0 {
				ldr.Errorf(s, "bad DS reloc for %s: %d", ldr.SymName(s), ldr.SymValue(rs))
			}
			o2 |= uint32(t) & 0xFFFC
		}
	case objabi.R_ADDRPOWER_TOCREL:
		o2 |= uint32(t) & 0xffff
	default:
		return -1
	}

	if target.IsBigEndian() {
		return int64(o1)<<32 | int64(o2)
	}
	return int64(o2)<<32 | int64(o1)
}

// archrelocaddr relocates a symbol address.
// This code is for linux only.
func archrelocaddr(ldr *loader.Loader, target *ld.Target, syms *ld.ArchSyms, r loader.Reloc, s loader.Sym, val int64) int64 {
	rs := r.Sym()
	if target.IsAIX() {
		ldr.Errorf(s, "archrelocaddr called for %s relocation\n", ldr.SymName(rs))
	}
	o1, o2 := unpackInstPair(target, val)

	// Verify resulting address fits within a 31 bit (2GB) address space.
	// This is a restriction arising  from the usage of lis (HA) + d-form
	// (LO) instruction sequences used to implement absolute relocations
	// on PPC64 prior to ISA 3.1 (P10). For consistency, maintain this
	// restriction for ISA 3.1 unless it becomes problematic.
	t := ldr.SymAddr(rs) + r.Add()
	if t < 0 || t >= 1<<31 {
		ldr.Errorf(s, "relocation for %s is too big (>=2G): 0x%x", ldr.SymName(s), ldr.SymValue(rs))
	}

	// Note, relocations imported from external objects may not have cleared bits
	// within a relocatable field. They need cleared before applying the relocation.
	switch r.Type() {
	case objabi.R_ADDRPOWER_PCREL34:
		// S + A - P
		t -= (ldr.SymValue(s) + int64(r.Off()))
		o1 &^= 0x3ffff
		o2 &^= 0x0ffff
		o1 |= computePrefix34HI(t)
		o2 |= computeLO(int32(t))
	case objabi.R_ADDRPOWER_D34:
		o1 &^= 0x3ffff
		o2 &^= 0x0ffff
		o1 |= computePrefix34HI(t)
		o2 |= computeLO(int32(t))
	case objabi.R_ADDRPOWER:
		o1 &^= 0xffff
		o2 &^= 0xffff
		o1 |= computeHA(int32(t))
		o2 |= computeLO(int32(t))
	case objabi.R_ADDRPOWER_DS:
		o1 &^= 0xffff
		o2 &^= 0xfffc
		o1 |= computeHA(int32(t))
		o2 |= computeLO(int32(t))
		if t&3 != 0 {
			ldr.Errorf(s, "bad DS reloc for %s: %d", ldr.SymName(s), ldr.SymValue(rs))
		}
	default:
		return -1
	}

	return packInstPair(target, o1, o2)
}

// Determine if the code was compiled so that the TOC register R2 is initialized and maintained.
func r2Valid(ctxt *ld.Link) bool {
	return isLinkingPIC(ctxt)
}

// Determine if this is linking a position-independent binary.
func isLinkingPIC(ctxt *ld.Link) bool {
	switch ctxt.BuildMode {
	case ld.BuildModeCArchive, ld.BuildModeCShared, ld.BuildModePIE, ld.BuildModeShared, ld.BuildModePlugin:
		return true
	}
	// -linkshared option
	return ctxt.IsSharedGoLink()
}

// resolve direct jump relocation r in s, and add trampoline if necessary.
func trampoline(ctxt *ld.Link, ldr *loader.Loader, ri int, rs, s loader.Sym) {

	// Trampolines are created if the branch offset is too large and the linker cannot insert a call stub to handle it.
	// For internal linking, trampolines are always created for long calls.
	// For external linking, the linker can insert a call stub to handle a long call, but depends on having the TOC address in
	// r2.  For those build modes with external linking where the TOC address is not maintained in r2, trampolines must be created.
	if ctxt.IsExternal() && r2Valid(ctxt) {
		// The TOC pointer is valid. The external linker will insert trampolines.
		return
	}

	relocs := ldr.Relocs(s)
	r := relocs.At(ri)
	var t int64
	// ldr.SymValue(rs) == 0 indicates a cross-package jump to a function that is not yet
	// laid out. Conservatively use a trampoline. This should be rare, as we lay out packages
	// in dependency order.
	if ldr.SymValue(rs) != 0 {
		t = ldr.SymValue(rs) + r.Add() - (ldr.SymValue(s) + int64(r.Off()))
	}
	switch r.Type() {
	case objabi.R_CALLPOWER:
		// If branch offset is too far then create a trampoline.
		if (ctxt.IsExternal() && ldr.SymSect(s) != ldr.SymSect(rs)) || (ctxt.IsInternal() && int64(int32(t<<6)>>6) != t) || ldr.SymValue(rs) == 0 || (*ld.FlagDebugTramp > 1 && ldr.SymPkg(s) != ldr.SymPkg(rs)) {
			var tramp loader.Sym
			for i := 0; ; i++ {

				// Using r.Add as part of the name is significant in functions like duffzero where the call
				// target is at some offset within the function.  Calls to duff+8 and duff+256 must appear as
				// distinct trampolines.

				oName := ldr.SymName(rs)
				name := oName
				if r.Add() == 0 {
					name += fmt.Sprintf("-tramp%d", i)
				} else {
					name += fmt.Sprintf("%+x-tramp%d", r.Add(), i)
				}

				// Look up the trampoline in case it already exists

				tramp = ldr.LookupOrCreateSym(name, int(ldr.SymVersion(rs)))
				if oName == "runtime.deferreturn" {
					ldr.SetIsDeferReturnTramp(tramp, true)
				}
				if ldr.SymValue(tramp) == 0 {
					break
				}
				// Note, the trampoline is always called directly. The addend of the original relocation is accounted for in the
				// trampoline itself.
				t = ldr.SymValue(tramp) - (ldr.SymValue(s) + int64(r.Off()))

				// With internal linking, the trampoline can be used if it is not too far.
				// With external linking, the trampoline must be in this section for it to be reused.
				if (ctxt.IsInternal() && int64(int32(t<<6)>>6) == t) || (ctxt.IsExternal() && ldr.SymSect(s) == ldr.SymSect(tramp)) {
					break
				}
			}
			if ldr.SymType(tramp) == 0 {
				trampb := ldr.MakeSymbolUpdater(tramp)
				ctxt.AddTramp(trampb, ldr.SymType(s))
				gentramp(ctxt, ldr, trampb, rs, r.Add())
			}
			sb := ldr.MakeSymbolUpdater(s)
			relocs := sb.Relocs()
			r := relocs.At(ri)
			r.SetSym(tramp)
			r.SetAdd(0) // This was folded into the trampoline target address
		}
	default:
		ctxt.Errorf(s, "trampoline called with non-jump reloc: %d (%s)", r.Type(), sym.RelocName(ctxt.Arch, r.Type()))
	}
}

func gentramp(ctxt *ld.Link, ldr *loader.Loader, tramp *loader.SymbolBuilder, target loader.Sym, offset int64) {
	tramp.SetSize(16) // 4 instructions
	P := make([]byte, tramp.Size())
	var o1, o2 uint32

	// ELFv2 save/restore functions use R0/R12 in special ways, therefore trampolines
	// as generated here will not always work correctly.
	if strings.HasPrefix(ldr.SymName(target), "runtime.elf_") {
		log.Fatalf("Internal linker does not support trampolines to ELFv2 ABI"+
			" register save/restore function %s", ldr.SymName(target))
	}

	if ctxt.IsAIX() {
		// On AIX, the address is retrieved with a TOC symbol.
		// For internal linking, the "Linux" way might still be used.
		// However, all text symbols are accessed with a TOC symbol as
		// text relocations aren't supposed to be possible.
		// So, keep using the external linking way to be more AIX friendly.
		o1 = uint32(OP_ADDIS_R12_R2) // addis r12,  r2, toctargetaddr hi
		o2 = uint32(OP_LD_R12_R12)   // ld    r12, r12, toctargetaddr lo

		toctramp := ldr.CreateSymForUpdate("TOC."+ldr.SymName(tramp.Sym()), 0)
		toctramp.SetType(sym.SXCOFFTOC)
		toctramp.AddAddrPlus(ctxt.Arch, target, offset)

		r, _ := tramp.AddRel(objabi.R_ADDRPOWER_TOCREL_DS)
		r.SetOff(0)
		r.SetSiz(8) // generates 2 relocations: HA + LO
		r.SetSym(toctramp.Sym())
	} else if hasPCrel {
		// pla r12, addr (PCrel). This works for static or PIC, with or without a valid TOC pointer.
		o1 = uint32(OP_PLA_PFX)
		o2 = uint32(OP_PLA_SFX_R12) // pla r12, addr

		// The trampoline's position is not known yet, insert a relocation.
		r, _ := tramp.AddRel(objabi.R_ADDRPOWER_PCREL34)
		r.SetOff(0)
		r.SetSiz(8) // This spans 2 words.
		r.SetSym(target)
		r.SetAdd(offset)
	} else {
		// Used for default build mode for an executable
		// Address of the call target is generated using
		// relocation and doesn't depend on r2 (TOC).
		o1 = uint32(OP_LIS_R12)      // lis  r12,targetaddr hi
		o2 = uint32(OP_ADDI_R12_R12) // addi r12,r12,targetaddr lo

		t := ldr.SymValue(target)
		if t == 0 || r2Valid(ctxt) || ctxt.IsExternal() {
			// Target address is unknown, generate relocations
			r, _ := tramp.AddRel(objabi.R_ADDRPOWER)
			if r2Valid(ctxt) {
				// Use a TOC relative address if R2 holds the TOC pointer
				o1 |= uint32(2 << 16) // Transform lis r31,ha into addis r31,r2,ha
				r.SetType(objabi.R_ADDRPOWER_TOCREL)
			}
			r.SetOff(0)
			r.SetSiz(8) // generates 2 relocations: HA + LO
			r.SetSym(target)
			r.SetAdd(offset)
		} else {
			// The target address is known, resolve it
			t += offset
			o1 |= (uint32(t) + 0x8000) >> 16 // HA
			o2 |= uint32(t) & 0xFFFF         // LO
		}
	}

	o3 := uint32(OP_MTCTR_R12) // mtctr r12
	o4 := uint32(OP_BCTR)      // bctr
	ctxt.Arch.ByteOrder.PutUint32(P, o1)
	ctxt.Arch.ByteOrder.PutUint32(P[4:], o2)
	ctxt.Arch.ByteOrder.PutUint32(P[8:], o3)
	ctxt.Arch.ByteOrder.PutUint32(P[12:], o4)
	tramp.SetData(P)
}

// Unpack a pair of 32 bit instruction words from
// a 64 bit relocation into instN and instN+1 in endian order.
func unpackInstPair(target *ld.Target, r int64) (uint32, uint32) {
	if target.IsBigEndian() {
		return uint32(r >> 32), uint32(r)
	}
	return uint32(r), uint32(r >> 32)
}

// Pack a pair of 32 bit instruction words o1, o2 into 64 bit relocation
// in endian order.
func packInstPair(target *ld.Target, o1, o2 uint32) int64 {
	if target.IsBigEndian() {
		return (int64(o1) << 32) | int64(o2)
	}
	return int64(o1) | (int64(o2) << 32)
}

// Compute the high-adjusted value (always a signed 32b value) per the ELF ABI.
// The returned value is always 0 <= x <= 0xFFFF.
func computeHA(val int32) uint32 {
	return uint32(uint16((val + 0x8000) >> 16))
}

// Compute the low value (the lower 16 bits of any 32b value) per the ELF ABI.
// The returned value is always 0 <= x <= 0xFFFF.
func computeLO(val int32) uint32 {
	return uint32(uint16(val))
}

// Compute the high 18 bits of a signed 34b constant. Used to pack the high 18 bits
// of a prefix34 relocation field. This assumes the input is already restricted to
// 34 bits.
func computePrefix34HI(val int64) uint32 {
	return uint32((val >> 16) & 0x3FFFF)
}

func computeTLSLEReloc(target *ld.Target, ldr *loader.Loader, rs, s loader.Sym) int64 {
	// The thread pointer points 0x7000 bytes after the start of the
	// thread local storage area as documented in section "3.7.2 TLS
	// Runtime Handling" of "Power Architecture 64-Bit ELF V2 ABI
	// Specification".
	v := ldr.SymValue(rs) - 0x7000
	if target.IsAIX() {
		// On AIX, the thread pointer points 0x7800 bytes after
		// the TLS.
		v -= 0x800
	}

	if int64(int32(v)) != v {
		ldr.Errorf(s, "TLS offset out of range %d", v)
	}
	return v
}

func archreloc(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, r loader.Reloc, s loader.Sym, val int64) (relocatedOffset int64, nExtReloc int, ok bool) {
	rs := r.Sym()
	if target.IsExternal() {
		// On AIX, relocations (except TLS ones) must be also done to the
		// value with the current addresses.
		switch rt := r.Type(); rt {
		default:
			if !target.IsAIX() {
				return val, nExtReloc, false
			}
		case objabi.R_POWER_TLS, objabi.R_POWER_TLS_IE_PCREL34, objabi.R_POWER_TLS_LE_TPREL34, objabi.R_ADDRPOWER_GOT_PCREL34:
			nExtReloc = 1
			return val, nExtReloc, true
		case objabi.R_POWER_TLS_LE, objabi.R_POWER_TLS_IE:
			if target.IsAIX() && rt == objabi.R_POWER_TLS_LE {
				// Fixup val, an addis/addi pair of instructions, which generate a 32b displacement
				// from the threadpointer (R13), into a 16b relocation. XCOFF only supports 16b
				// TLS LE relocations. Likewise, verify this is an addis/addi sequence.
				const expectedOpcodes = 0x3C00000038000000
				const expectedOpmasks = 0xFC000000FC000000
				if uint64(val)&expectedOpmasks != expectedOpcodes {
					ldr.Errorf(s, "relocation for %s+%d is not an addis/addi pair: %16x", ldr.SymName(rs), r.Off(), uint64(val))
				}
				nval := (int64(uint32(0x380d0000)) | val&0x03e00000) << 32 // addi rX, r13, $0
				nval |= int64(OP_NOP)                                      // nop
				val = nval
				nExtReloc = 1
			} else {
				nExtReloc = 2
			}
			return val, nExtReloc, true
		case objabi.R_ADDRPOWER,
			objabi.R_ADDRPOWER_DS,
			objabi.R_ADDRPOWER_TOCREL,
			objabi.R_ADDRPOWER_TOCREL_DS,
			objabi.R_ADDRPOWER_GOT,
			objabi.R_ADDRPOWER_PCREL:
			nExtReloc = 2 // need two ELF relocations, see elfreloc1
			if !target.IsAIX() {
				return val, nExtReloc, true
			}
		case objabi.R_CALLPOWER, objabi.R_ADDRPOWER_D34, objabi.R_ADDRPOWER_PCREL34:
			nExtReloc = 1
			if !target.IsAIX() {
				return val, nExtReloc, true
			}
		}
	}

	switch r.Type() {
	case objabi.R_ADDRPOWER_TOCREL, objabi.R_ADDRPOWER_TOCREL_DS:
		return archreloctoc(ldr, target, syms, r, s, val), nExtReloc, true
	case objabi.R_ADDRPOWER, objabi.R_ADDRPOWER_DS, objabi.R_ADDRPOWER_D34, objabi.R_ADDRPOWER_PCREL34:
		return archrelocaddr(ldr, target, syms, r, s, val), nExtReloc, true
	case objabi.R_CALLPOWER:
		// Bits 6 through 29 = (S + A - P) >> 2

		t := ldr.SymValue(rs) + r.Add() - (ldr.SymValue(s) + int64(r.Off()))

		tgtName := ldr.SymName(rs)

		// If we are linking PIE or shared code, non-PCrel golang generated object files have an extra 2 instruction prologue
		// to regenerate the TOC pointer from R12.  The exception are two special case functions tested below.  Note,
		// local call offsets for externally generated objects are accounted for when converting into golang relocs.
		if !hasPCrel && !ldr.AttrExternal(rs) && ldr.AttrShared(rs) && tgtName != "runtime.duffzero" && tgtName != "runtime.duffcopy" {
			// Furthermore, only apply the offset if the target looks like the start of a function call.
			if r.Add() == 0 && ldr.SymType(rs).IsText() {
				t += 8
			}
		}

		if t&3 != 0 {
			ldr.Errorf(s, "relocation for %s+%d is not aligned: %d", ldr.SymName(rs), r.Off(), t)
		}
		// If branch offset is too far then create a trampoline.

		if int64(int32(t<<6)>>6) != t {
			ldr.Errorf(s, "direct call too far: %s %x", ldr.SymName(rs), t)
		}
		return val | int64(uint32(t)&^0xfc000003), nExtReloc, true
	case objabi.R_POWER_TOC: // S + A - .TOC.
		return ldr.SymValue(rs) + r.Add() - symtoc(ldr, syms, s), nExtReloc, true

	case objabi.R_ADDRPOWER_PCREL: // S + A - P
		t := ldr.SymValue(rs) + r.Add() - (ldr.SymValue(s) + int64(r.Off()))
		ha, l := unpackInstPair(target, val)
		l |= computeLO(int32(t))
		ha |= computeHA(int32(t))
		return packInstPair(target, ha, l), nExtReloc, true

	case objabi.R_POWER_TLS:
		const OP_ADD = 31<<26 | 266<<1
		const MASK_OP_ADD = 0x3F<<26 | 0x1FF<<1
		if val&MASK_OP_ADD != OP_ADD {
			ldr.Errorf(s, "R_POWER_TLS reloc only supports XO form ADD, not %08X", val)
		}
		// Verify RB is R13 in ADD RA,RB,RT.
		if (val>>11)&0x1F != 13 {
			// If external linking is made to support this, it may expect the linker to rewrite RB.
			ldr.Errorf(s, "R_POWER_TLS reloc requires R13 in RB (%08X).", uint32(val))
		}
		return val, nExtReloc, true

	case objabi.R_POWER_TLS_IE:
		// Convert TLS_IE relocation to TLS_LE if supported.
		if !(target.IsPIE() && target.IsElf()) {
			log.Fatalf("cannot handle R_POWER_TLS_IE (sym %s) when linking non-PIE, non-ELF binaries internally", ldr.SymName(s))
		}

		// We are an ELF binary, we can safely convert to TLS_LE from:
		// addis to, r2, x@got@tprel@ha
		// ld to, to, x@got@tprel@l(to)
		//
		// to TLS_LE by converting to:
		// addis to, r0, x@tprel@ha
		// addi to, to, x@tprel@l(to)

		const OP_MASK = 0x3F << 26
		const OP_RA_MASK = 0x1F << 16
		// convert r2 to r0, and ld to addi
		mask := packInstPair(target, OP_RA_MASK, OP_MASK)
		addi_op := packInstPair(target, 0, OP_ADDI)
		val &^= mask
		val |= addi_op
		fallthrough

	case objabi.R_POWER_TLS_LE:
		v := computeTLSLEReloc(target, ldr, rs, s)
		o1, o2 := unpackInstPair(target, val)
		o1 |= computeHA(int32(v))
		o2 |= computeLO(int32(v))
		return packInstPair(target, o1, o2), nExtReloc, true

	case objabi.R_POWER_TLS_IE_PCREL34:
		// Convert TLS_IE relocation to TLS_LE if supported.
		if !(target.IsPIE() && target.IsElf()) {
			log.Fatalf("cannot handle R_POWER_TLS_IE (sym %s) when linking non-PIE, non-ELF binaries internally", ldr.SymName(s))
		}

		// We are an ELF binary, we can safely convert to TLS_LE_TPREL34 from:
		// pld rX, x@got@tprel@pcrel
		//
		// to TLS_LE_TPREL32 by converting to:
		// pla rX, x@tprel

		const OP_MASK_PFX = 0xFFFFFFFF        // Discard prefix word
		const OP_MASK = (0x3F << 26) | 0xFFFF // Preserve RT, RA
		const OP_PFX = 1<<26 | 2<<24
		const OP_PLA = 14 << 26
		mask := packInstPair(target, OP_MASK_PFX, OP_MASK)
		pla_op := packInstPair(target, OP_PFX, OP_PLA)
		val &^= mask
		val |= pla_op
		fallthrough

	case objabi.R_POWER_TLS_LE_TPREL34:
		v := computeTLSLEReloc(target, ldr, rs, s)
		o1, o2 := unpackInstPair(target, val)
		o1 |= computePrefix34HI(v)
		o2 |= computeLO(int32(v))
		return packInstPair(target, o1, o2), nExtReloc, true
	}

	return val, nExtReloc, false
}

func archrelocvariant(target *ld.Target, ldr *loader.Loader, r loader.Reloc, rv sym.RelocVariant, s loader.Sym, t int64, p []byte) (relocatedOffset int64) {
	rs := r.Sym()
	switch rv & sym.RV_TYPE_MASK {
	default:
		ldr.Errorf(s, "unexpected relocation variant %d", rv)
		fallthrough

	case sym.RV_NONE:
		return t

	case sym.RV_POWER_LO:
		if rv&sym.RV_CHECK_OVERFLOW != 0 {
			// Whether to check for signed or unsigned
			// overflow depends on the instruction
			var o1 uint32
			if target.IsBigEndian() {
				o1 = binary.BigEndian.Uint32(p[r.Off()-2:])
			} else {
				o1 = binary.LittleEndian.Uint32(p[r.Off():])
			}
			switch o1 >> 26 {
			case 24, // ori
				26, // xori
				28: // andi
				if t>>16 != 0 {
					goto overflow
				}

			default:
				if int64(int16(t)) != t {
					goto overflow
				}
			}
		}

		return int64(int16(t))

	case sym.RV_POWER_HA:
		t += 0x8000
		fallthrough

		// Fallthrough
	case sym.RV_POWER_HI:
		t >>= 16

		if rv&sym.RV_CHECK_OVERFLOW != 0 {
			// Whether to check for signed or unsigned
			// overflow depends on the instruction
			var o1 uint32
			if target.IsBigEndian() {
				o1 = binary.BigEndian.Uint32(p[r.Off()-2:])
			} else {
				o1 = binary.LittleEndian.Uint32(p[r.Off():])
			}
			switch o1 >> 26 {
			case 25, // oris
				27, // xoris
				29: // andis
				if t>>16 != 0 {
					goto overflow
				}

			default:
				if int64(int16(t)) != t {
					goto overflow
				}
			}
		}

		return int64(int16(t))

	case sym.RV_POWER_DS:
		var o1 uint32
		if target.IsBigEndian() {
			o1 = uint32(binary.BigEndian.Uint16(p[r.Off():]))
		} else {
			o1 = uint32(binary.LittleEndian.Uint16(p[r.Off():]))
		}
		if t&3 != 0 {
			ldr.Errorf(s, "relocation for %s+%d is not aligned: %d", ldr.SymName(rs), r.Off(), t)
		}
		if (rv&sym.RV_CHECK_OVERFLOW != 0) && int64(int16(t)) != t {
			goto overflow
		}
		return int64(o1)&0x3 | int64(int16(t))
	}

overflow:
	ldr.Errorf(s, "relocation for %s+%d is too big: %d", ldr.SymName(rs), r.Off(), t)
	return t
}

func extreloc(target *ld.Target, ldr *loader.Loader, r loader.Reloc, s loader.Sym) (loader.ExtReloc, bool) {
	switch r.Type() {
	case objabi.R_POWER_TLS, objabi.R_POWER_TLS_LE, objabi.R_POWER_TLS_IE, objabi.R_POWER_TLS_IE_PCREL34, objabi.R_POWER_TLS_LE_TPREL34, objabi.R_CALLPOWER:
		return ld.ExtrelocSimple(ldr, r), true
	case objabi.R_ADDRPOWER,
		objabi.R_ADDRPOWER_DS,
		objabi.R_ADDRPOWER_TOCREL,
		objabi.R_ADDRPOWER_TOCREL_DS,
		objabi.R_ADDRPOWER_GOT,
		objabi.R_ADDRPOWER_GOT_PCREL34,
		objabi.R_ADDRPOWER_PCREL,
		objabi.R_ADDRPOWER_D34,
		objabi.R_ADDRPOWER_PCREL34:
		return ld.ExtrelocViaOuterSym(ldr, r, s), true
	}
	return loader.ExtReloc{}, false
}

func addpltsym(ctxt *ld.Link, ldr *loader.Loader, s loader.Sym) {
	if ldr.SymPlt(s) >= 0 {
		return
	}

	ld.Adddynsym(ldr, &ctxt.Target, &ctxt.ArchSyms, s)

	if ctxt.IsELF {
		plt := ldr.MakeSymbolUpdater(ctxt.PLT)
		rela := ldr.MakeSymbolUpdater(ctxt.RelaPLT)
		if plt.Size() == 0 {
			panic("plt is not set up")
		}

		// Create the glink resolver if necessary
		glink := ensureglinkresolver(ctxt, ldr)

		// Write symbol resolver stub (just a branch to the
		// glink resolver stub)
		rel, _ := glink.AddRel(objabi.R_CALLPOWER)
		rel.SetOff(int32(glink.Size()))
		rel.SetSiz(4)
		rel.SetSym(glink.Sym())
		glink.AddUint32(ctxt.Arch, 0x48000000) // b .glink

		// In the ppc64 ABI, the dynamic linker is responsible
		// for writing the entire PLT.  We just need to
		// reserve 8 bytes for each PLT entry and generate a
		// JMP_SLOT dynamic relocation for it.
		//
		// TODO(austin): ABI v1 is different
		ldr.SetPlt(s, int32(plt.Size()))

		plt.Grow(plt.Size() + 8)
		plt.SetSize(plt.Size() + 8)

		rela.AddAddrPlus(ctxt.Arch, plt.Sym(), int64(ldr.SymPlt(s)))
		rela.AddUint64(ctxt.Arch, elf.R_INFO(uint32(ldr.SymDynid(s)), uint32(elf.R_PPC64_JMP_SLOT)))
		rela.AddUint64(ctxt.Arch, 0)
	} else {
		ctxt.Errorf(s, "addpltsym: unsupported binary format")
	}
}

// Generate the glink resolver stub if necessary and return the .glink section.
func ensureglinkresolver(ctxt *ld.Link, ldr *loader.Loader) *loader.SymbolBuilder {
	glink := ldr.CreateSymForUpdate(".glink", 0)
	if glink.Size() != 0 {
		return glink
	}

	// This is essentially the resolver from the ppc64 ELFv2 ABI.
	// At entry, r12 holds the address of the symbol resolver stub
	// for the target routine and the argument registers hold the
	// arguments for the target routine.
	//
	// PC-rel offsets are computed once the final codesize of the
	// resolver is known.
	//
	// This stub is PIC, so first get the PC of label 1 into r11.
	glink.AddUint32(ctxt.Arch, OP_MFLR_R0) // mflr r0
	glink.AddUint32(ctxt.Arch, OP_BCL_NIA) // bcl 20,31,1f
	glink.AddUint32(ctxt.Arch, 0x7d6802a6) // 1: mflr r11
	glink.AddUint32(ctxt.Arch, OP_MTLR_R0) // mtlr r0

	// Compute the .plt array index from the entry point address
	// into r0. This is computed relative to label 1 above.
	glink.AddUint32(ctxt.Arch, 0x38000000) // li r0,-(res_0-1b)
	glink.AddUint32(ctxt.Arch, 0x7c006214) // add r0,r0,r12
	glink.AddUint32(ctxt.Arch, 0x7c0b0050) // sub r0,r0,r11
	glink.AddUint32(ctxt.Arch, 0x7800f082) // srdi r0,r0,2

	// Load the PC-rel offset of ".plt - 1b", and add it to 1b.
	// This is stored after this stub and before the resolvers.
	glink.AddUint32(ctxt.Arch, 0xe98b0000) // ld r12,res_0-1b-8(r11)
	glink.AddUint32(ctxt.Arch, 0x7d6b6214) // add r11,r11,r12

	// Load r12 = dynamic resolver address and r11 = DSO
	// identifier from the first two doublewords of the PLT.
	glink.AddUint32(ctxt.Arch, 0xe98b0000) // ld r12,0(r11)
	glink.AddUint32(ctxt.Arch, 0xe96b0008) // ld r11,8(r11)

	// Jump to the dynamic resolver
	glink.AddUint32(ctxt.Arch, OP_MTCTR_R12) // mtctr r12
	glink.AddUint32(ctxt.Arch, OP_BCTR)      // bctr

	// Store the PC-rel offset to the PLT
	r, _ := glink.AddRel(objabi.R_PCREL)
	r.SetSym(ctxt.PLT)
	r.SetSiz(8)
	r.SetOff(int32(glink.Size()))
	r.SetAdd(glink.Size())        // Adjust the offset to be relative to label 1 above.
	glink.AddUint64(ctxt.Arch, 0) // The offset to the PLT.

	// Resolve PC-rel offsets above now the final size of the stub is known.
	res0m1b := glink.Size() - 8 // res_0 - 1b
	glink.SetUint32(ctxt.Arch, 16, 0x38000000|uint32(uint16(-res0m1b)))
	glink.SetUint32(ctxt.Arch, 32, 0xe98b0000|uint32(uint16(res0m1b-8)))

	// The symbol resolvers must immediately follow.
	//   res_0:

	// Add DT_PPC64_GLINK .dynamic entry, which points to 32 bytes
	// before the first symbol resolver stub.
	du := ldr.MakeSymbolUpdater(ctxt.Dynamic)
	ld.Elfwritedynentsymplus(ctxt, du, elf.DT_PPC64_GLINK, glink.Sym(), glink.Size()-32)

	return glink
}
```