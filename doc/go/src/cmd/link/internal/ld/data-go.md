Response:
The user wants to understand the functionality of the provided Go code snippet. This code is part of the Go linker (`cmd/link`). I need to analyze the code and identify its main purposes. Based on the package name (`ld`), the file name (`data.go`), and the imported packages, the code seems to be involved in data layout and processing during the linking phase.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the Core Functionality:**  The presence of functions like `trampoline`, `relocsym`, `windynrelocsym`, `dynrelocsym`, `dodata`, `CodeblkPad`, `DatblkBytes`, and the handling of different symbol types (e.g., `SDATA`, `SBSS`, `STEXT`) strongly suggests this code deals with:
    * **Relocations:** Processing and applying relocations.
    * **Trampolines:** Inserting trampolines for long jumps/calls.
    * **Dynamic Linking:** Handling relocations for dynamic libraries.
    * **Data Layout:** Organizing and laying out data sections.
    * **Garbage Collection Metadata:**  Generating metadata for the garbage collector.

2. **Break Down Key Functions:**

    * **`trampoline`:**  The name is quite indicative. It likely detects if a direct call or jump is too far and inserts a trampoline to bridge the distance.

    * **`relocsym`:** This function clearly handles the core relocation logic. It iterates through relocations for a symbol and applies them, potentially involving architecture-specific logic. The handling of `target.IsExternal()` is crucial for understanding its role in external linking.

    * **`windynrelocsym`:** The "windyn" prefix suggests Windows-specific dynamic linking. The comments confirm it's about handling relocations to symbols in DLLs.

    * **`dynrelocsym`:** This function appears to handle dynamic relocations for various platforms, likely creating entries in dynamic linking tables.

    * **`dodata`:** This seems to be a high-level function responsible for laying out data sections. It collects symbols, sorts them, and assigns them to sections. The interaction with `GCProg` points to garbage collection metadata generation.

    * **`CodeblkPad`, `DatblkBytes`, `writeBlocks`, `writeBlock`:** These functions deal with writing the code and data blocks to the output file, possibly handling padding and parallel writing.

3. **Infer Go Language Feature Implementations:**

    * **Relocations:**  This is a fundamental part of linking. The code handles different relocation types (`objabi.R_ADDR`, `objabi.R_PCREL`, etc.) and applies them by modifying the symbol's content.

    * **Trampolines:**  The code checks for direct calls/jumps exceeding the allowed range and inserts small code snippets (trampolines) to reach the target. This is a common technique on architectures with limited branch offsets.

    * **Dynamic Linking:** The `windynrelocsym` and `dynrelocsym` functions, along with the handling of `SDYNIMPORT` symbols, are key aspects of implementing dynamic linking. This involves creating entries in the Global Offset Table (GOT) and Procedure Linkage Table (PLT).

    * **Data Layout:**  `dodata` orchestrates the organization of data sections, taking into account alignment, symbol types, and the needs of the garbage collector.

    * **String Variable Initialization (`addstrdata`):** The code allows initializing string variables using the `-X` linker flag.

    * **Garbage Collection Metadata:** The `GCProg` struct and its methods are responsible for generating metadata that describes the locations of pointers within data sections, which the garbage collector uses.

4. **Provide Code Examples:**  For key features like relocations and trampolines, providing simplified Go code examples helps illustrate the concept. The relocation example shows how a value is patched based on the target symbol's address. The trampoline example demonstrates the insertion of an intermediary jump.

5. **Explain Command-Line Parameters:** The `-X` flag's role in initializing string variables is a specific command-line interaction that needs explanation.

6. **Identify Potential Pitfalls:**  Focus on common errors developers might encounter when working with linking-related concepts. Incorrect use of the `-X` flag or misunderstandings about symbol reachability are good examples.

7. **Summarize the Functionality:** Condense the findings into a concise overview of the code's main roles within the Go linker.

8. **Structure the Output:** Organize the information logically with clear headings and bullet points for readability. Follow the user's request to provide examples, explain command-line parameters, and highlight potential errors.

**Self-Correction/Refinement during thought process:**

* **Initial thought:**  The code might be directly writing to the output file. **Correction:**  It seems to be working with an abstraction (`OutBuf`) which likely handles the actual output writing, potentially in parallel.
* **Initial thought:** Focus only on the most obvious functions. **Correction:**  Realized the importance of including helper functions like `writeBlocks` and `writeBlock` to provide a more complete picture of the data processing.
* **Initial thought:**  Provide highly technical details about relocation types. **Correction:**  Keep the explanation at a higher level, focusing on the *purpose* of relocations rather than every specific type. The code examples can provide more concrete illustrations.
* **Ensure code examples are clear and concise:** Avoid overly complex examples that might obscure the core concept. Focus on demonstrating the mechanism rather than all possible scenarios.
这是 `go/src/cmd/link/internal/ld/data.go` 文件的第一部分，其主要功能可以归纳为：

**核心功能：处理链接过程中的数据布局和重定位**

更具体来说，这部分代码负责以下几个关键任务：

1. **辅助生成可执行文件的代码和数据段：**  定义了在链接过程中如何处理代码块和数据块，包括填充、写入和地址分配。
2. **处理函数间的跳转和调用（Trampoline）：**  针对某些架构（如 ARM, ARM64, LOONG64, PPC64, RISCV64），当函数间的直接跳转或调用距离过远时，会插入“跳板”（trampoline）代码来解决这个问题。
3. **处理符号的重定位（Relocation）：**  负责解析和应用符号的重定位信息，将符号引用解析为实际的内存地址或偏移量。这包括处理内部重定位和为外部链接器准备外部重定位信息。
4. **处理 Windows 平台的动态链接（Windyn Relocation）：**  针对 Windows 平台，特殊处理链接到 DLL 中符号的重定位，包括间接引用和直接引用的处理，并生成跳转表。
5. **处理动态链接的重定位（Dynamic Relocation）：**  为动态链接生成必要的重定位信息，以便动态链接器在运行时解析符号。
6. **初始化字符串变量（String Data）：**  允许通过 `-X` 命令行参数设置程序中字符串变量的初始值。
7. **生成垃圾回收所需的元数据（GC Program）：**  为数据段生成垃圾回收器所需的元数据，描述数据结构中的指针信息。
8. **数据段的组织和分配：**  `dodata` 函数是这部分的核心，它负责收集各种类型的数据符号，并将它们分配到不同的数据段（如 `.data`, `.bss`, `.rodata`, `.noptrdata`, `.init_array` 等）。
9. **处理符号对齐：**  确保符号在内存中按照正确的边界对齐。

**以下是一些具体功能的代码示例和推理：**

**1. 跳板 (Trampoline) 功能的实现**

**推理：** `trampoline` 函数会检查函数中的重定位，判断目标符号是否可达，如果距离过远，则会调用 `thearch.Trampoline` 函数来插入跳板代码。

**假设输入：** 一个 ARM 架构的目标文件，其中一个函数 `caller` 需要调用另一个函数 `callee`，但 `callee` 的地址距离 `caller` 的地址太远，超出了直接跳转指令的范围。

**Go 代码示例（伪代码，`thearch.Trampoline` 的具体实现因架构而异）：**

```go
// 假设的 thearch.Trampoline 函数实现（ARM 架构）
func armTrampoline(ctxt *Link, ldr *loader.Loader, ri int, rs loader.Sym, s loader.Sym) {
	// 创建一个新的符号，用于存放跳板代码
	trampolineSym := ldr.CreateSymForUpdate(ldr.SymName(s)+".trampoline."+ldr.SymName(rs), 0)
	trampolineSym.SetType(sym.STEXT)
	trampolineSym.SetSize(8) // 假设跳板代码大小为 8 字节

	// 生成跳板代码，例如：
	// LDR PC, [PC, #-4] ; 加载目标地址到 PC 寄存器
	trampolineCode := []byte{0xE5, 0x1F, 0xF0, 0x04}
	trampolineSym.SetData(trampolineCode)

	// 在调用者的重定位位置，将目标符号修改为跳板符号
	rel := ldr.Relocs(s).At(ri)
	rel.SetSym(trampolineSym.Sym())
	rel.SetType(objabi.R_PCREL) // 修改重定位类型为 PC 相对

	// 添加一个重定位，将跳板代码中的目标地址指向真正的 callee
	ldr.AddRel(trampolineSym.Sym(), loader.Reloc{
		Offset: 4, // 目标地址在跳板代码中的偏移
		Siz:    4,
		Type:   objabi.R_ADDR, // 绝对地址重定位
		Sym:    rs,
	})
}
```

**输出：**  链接器会在 `caller` 函数中插入一个指向跳板的短跳转指令，并在新创建的跳板符号中生成代码，该代码会加载 `callee` 的实际地址并跳转过去。

**2. 重定位 (Relocation) 功能的实现**

**推理：** `relocsym` 函数根据重定位类型，读取或计算目标地址，并将其写入到需要重定位的位置。

**假设输入：** 一个 AMD64 架构的目标文件，其中一个函数 `funcA` 中包含一条指令，需要调用另一个函数 `funcB`，并且有一个 `R_PCREL` 类型的重定位记录指向 `funcB`。

**Go 代码示例：**

```go
func (st *relocSymState) relocsym(s loader.Sym, P []byte) {
	// ... (省略部分代码) ...
	for ri := 0; ri < relocs.Count(); ri++ {
		r := relocs.At(ri)
		off := r.Off()
		siz := int32(r.Siz())
		rs := r.Sym()
		rt := r.Type()

		if rt == objabi.R_PCREL {
			// 计算 funcB 的地址
			targetAddr := st.ldr.SymValue(rs)

			// 计算相对偏移量
			relOffset := targetAddr - (st.ldr.SymValue(s) + int64(off) + int64(siz))

			// 将偏移量写入到 P 的相应位置 (假设 siz 为 4)
			st.target.Arch.ByteOrder.PutUint32(P[off:], uint32(relOffset))
		}
		// ... (处理其他重定位类型) ...
	}
}
```

**输入：**  `funcA` 的地址为 `0x1000`，重定位发生在 `funcA` 的偏移 `0x10` 处，大小为 4 字节。`funcB` 的地址为 `0x2000`。

**输出：** 在 `funcA` 的地址 `0x1010` 开始的 4 个字节会被写入 `0x2000 - (0x1000 + 0x10 + 4) = 0x2000 - 0x1014 = 0xFEEC` (小端序)。

**3. 初始化字符串变量 (-X 标志)**

**命令行参数处理：**  `addstrdata1` 函数解析 `-X` 标志的参数，提取包名、变量名和值。`dostrdata` 函数遍历解析后的信息，调用 `addstrdata` 来实际初始化变量。

**详细介绍：**

当使用 `go build -ldflags "-X importpath.varname=value"` 命令时：

* `-ldflags`  指示将参数传递给链接器。
* `-X importpath.varname=value`  告诉链接器要设置 `importpath` 包中的名为 `varname` 的字符串变量的值为 `value`。

`addstrdata1` 会解析这个字符串，例如，如果参数是 `"main.GlobalString=Hello"`，则 `pkg` 将是 `"main"`，`name` 将是 `"main.GlobalString"`，`value` 将是 `"Hello"`。

`addstrdata` 函数会找到对应的符号，创建一个新的只读数据符号来存储字符串的值，并将原始字符串变量的地址指向这个新的符号，同时设置其长度。

**使用者易犯错的点：**

* **`-X` 标志的参数格式错误：** 必须是 `importpath.name=value` 的形式，包名和变量名之间用点号分隔，等号后面是字符串值。
  * **错误示例：** `go build -ldflags "-X mainGlobalString=Hello"` (缺少点号)
  * **错误示例：** `go build -ldflags "-X main.GlobalString Hello"` (缺少等号)
* **指定的变量不是字符串类型：**  `-X` 标志只能用于初始化字符串类型的变量。
  * **错误示例：** 尝试用 `-X` 初始化一个整型变量。
* **指定的包或变量不存在或不可达：**  如果指定的包名或变量名在程序中不存在或者链接器无法访问到，初始化会失败。

**功能归纳:**

`go/src/cmd/link/internal/ld/data.go` 的第一部分主要负责在 Go 语言链接过程中处理代码和数据的布局、重定位、动态链接以及一些特定的初始化任务，为最终生成可执行文件或共享库奠定基础。它包含了处理架构差异、优化跳转距离、与操作系统动态链接机制交互以及为运行时环境准备必要元数据的关键逻辑。

Prompt: 
```
这是路径为go/src/cmd/link/internal/ld/data.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能

"""
// Derived from Inferno utils/6l/obj.c and utils/6l/span.c
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/6l/obj.c
// https://bitbucket.org/inferno-os/inferno-os/src/master/utils/6l/span.c
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

package ld

import (
	"bytes"
	"cmd/internal/gcprog"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmd/link/internal/loader"
	"cmd/link/internal/loadpe"
	"cmd/link/internal/sym"
	"compress/zlib"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"internal/abi"
	"log"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// isRuntimeDepPkg reports whether pkg is the runtime package or its dependency.
// TODO: just compute from the runtime package, and remove this hardcoded list.
func isRuntimeDepPkg(pkg string) bool {
	switch pkg {
	case "runtime",
		"sync/atomic",  // runtime may call to sync/atomic, due to go:linkname // TODO: this is not true?
		"internal/abi", // used by reflectcall (and maybe more)
		"internal/asan",
		"internal/bytealg", // for IndexByte
		"internal/byteorder",
		"internal/chacha8rand", // for rand
		"internal/coverage/rtcov",
		"internal/cpu", // for cpu features
		"internal/goarch",
		"internal/godebugs",
		"internal/goexperiment",
		"internal/goos",
		"internal/msan",
		"internal/profilerecord",
		"internal/race",
		"internal/stringslite",
		"unsafe":
		return true
	}
	return (strings.HasPrefix(pkg, "runtime/internal/") || strings.HasPrefix(pkg, "internal/runtime/")) &&
		!strings.HasSuffix(pkg, "_test")
}

// Estimate the max size needed to hold any new trampolines created for this function. This
// is used to determine when the section can be split if it becomes too large, to ensure that
// the trampolines are in the same section as the function that uses them.
func maxSizeTrampolines(ctxt *Link, ldr *loader.Loader, s loader.Sym, isTramp bool) uint64 {
	// If thearch.Trampoline is nil, then trampoline support is not available on this arch.
	// A trampoline does not need any dependent trampolines.
	if thearch.Trampoline == nil || isTramp {
		return 0
	}

	n := uint64(0)
	relocs := ldr.Relocs(s)
	for ri := 0; ri < relocs.Count(); ri++ {
		r := relocs.At(ri)
		if r.Type().IsDirectCallOrJump() {
			n++
		}
	}

	switch {
	case ctxt.IsARM():
		return n * 20 // Trampolines in ARM range from 3 to 5 instructions.
	case ctxt.IsARM64():
		return n * 12 // Trampolines in ARM64 are 3 instructions.
	case ctxt.IsLOONG64():
		return n * 12 // Trampolines in LOONG64 are 3 instructions.
	case ctxt.IsPPC64():
		return n * 16 // Trampolines in PPC64 are 4 instructions.
	case ctxt.IsRISCV64():
		return n * 8 // Trampolines in RISCV64 are 2 instructions.
	}
	panic("unreachable")
}

// Detect too-far jumps in function s, and add trampolines if necessary.
// ARM, LOONG64, PPC64, PPC64LE and RISCV64 support trampoline insertion for internal
// and external linking. On PPC64 and PPC64LE the text sections might be split
// but will still insert trampolines where necessary.
func trampoline(ctxt *Link, s loader.Sym) {
	if thearch.Trampoline == nil {
		return // no need or no support of trampolines on this arch
	}

	ldr := ctxt.loader
	relocs := ldr.Relocs(s)
	for ri := 0; ri < relocs.Count(); ri++ {
		r := relocs.At(ri)
		rt := r.Type()
		if !rt.IsDirectCallOrJump() && !isPLTCall(ctxt.Arch, rt) {
			continue
		}
		rs := r.Sym()
		if !ldr.AttrReachable(rs) || ldr.SymType(rs) == sym.Sxxx {
			continue // something is wrong. skip it here and we'll emit a better error later
		}

		if ldr.SymValue(rs) == 0 && ldr.SymType(rs) != sym.SDYNIMPORT && ldr.SymType(rs) != sym.SUNDEFEXT {
			// Symbols in the same package are laid out together (if we
			// don't randomize the function order).
			// Except that if SymPkg(s) == "", it is a host object symbol
			// which may call an external symbol via PLT.
			if ldr.SymPkg(s) != "" && ldr.SymPkg(rs) == ldr.SymPkg(s) && ldr.SymType(rs) == ldr.SymType(s) && *flagRandLayout == 0 {
				// RISC-V is only able to reach +/-1MiB via a JAL instruction.
				// We need to generate a trampoline when an address is
				// currently unknown.
				if !ctxt.Target.IsRISCV64() {
					continue
				}
			}
			// Runtime packages are laid out together.
			if isRuntimeDepPkg(ldr.SymPkg(s)) && isRuntimeDepPkg(ldr.SymPkg(rs)) && *flagRandLayout == 0 {
				continue
			}
		}
		thearch.Trampoline(ctxt, ldr, ri, rs, s)
	}
}

// whether rt is a (host object) relocation that will be turned into
// a call to PLT.
func isPLTCall(arch *sys.Arch, rt objabi.RelocType) bool {
	const pcrel = 1
	switch uint32(arch.Family) | uint32(rt)<<8 {
	// ARM64
	case uint32(sys.ARM64) | uint32(objabi.ElfRelocOffset+objabi.RelocType(elf.R_AARCH64_CALL26))<<8,
		uint32(sys.ARM64) | uint32(objabi.ElfRelocOffset+objabi.RelocType(elf.R_AARCH64_JUMP26))<<8,
		uint32(sys.ARM64) | uint32(objabi.MachoRelocOffset+MACHO_ARM64_RELOC_BRANCH26*2+pcrel)<<8:
		return true

	// ARM
	case uint32(sys.ARM) | uint32(objabi.ElfRelocOffset+objabi.RelocType(elf.R_ARM_CALL))<<8,
		uint32(sys.ARM) | uint32(objabi.ElfRelocOffset+objabi.RelocType(elf.R_ARM_PC24))<<8,
		uint32(sys.ARM) | uint32(objabi.ElfRelocOffset+objabi.RelocType(elf.R_ARM_JUMP24))<<8:
		return true

	// Loong64
	case uint32(sys.Loong64) | uint32(objabi.ElfRelocOffset+objabi.RelocType(elf.R_LARCH_B26))<<8:
		return true
	}
	// TODO: other architectures.
	return false
}

// FoldSubSymbolOffset computes the offset of symbol s to its top-level outer
// symbol. Returns the top-level symbol and the offset.
// This is used in generating external relocations.
func FoldSubSymbolOffset(ldr *loader.Loader, s loader.Sym) (loader.Sym, int64) {
	outer := ldr.OuterSym(s)
	off := int64(0)
	if outer != 0 {
		off += ldr.SymValue(s) - ldr.SymValue(outer)
		s = outer
	}
	return s, off
}

// relocsym resolve relocations in "s", updating the symbol's content
// in "P".
// The main loop walks through the list of relocations attached to "s"
// and resolves them where applicable. Relocations are often
// architecture-specific, requiring calls into the 'archreloc' and/or
// 'archrelocvariant' functions for the architecture. When external
// linking is in effect, it may not be  possible to completely resolve
// the address/offset for a symbol, in which case the goal is to lay
// the groundwork for turning a given relocation into an external reloc
// (to be applied by the external linker). For more on how relocations
// work in general, see
//
//	"Linkers and Loaders", by John R. Levine (Morgan Kaufmann, 1999), ch. 7
//
// This is a performance-critical function for the linker; be careful
// to avoid introducing unnecessary allocations in the main loop.
func (st *relocSymState) relocsym(s loader.Sym, P []byte) {
	ldr := st.ldr
	relocs := ldr.Relocs(s)
	if relocs.Count() == 0 {
		return
	}
	target := st.target
	syms := st.syms
	nExtReloc := 0 // number of external relocations
	for ri := 0; ri < relocs.Count(); ri++ {
		r := relocs.At(ri)
		off := r.Off()
		siz := int32(r.Siz())
		rs := r.Sym()
		rt := r.Type()
		weak := r.Weak()
		if off < 0 || off+siz > int32(len(P)) {
			rname := ""
			if rs != 0 {
				rname = ldr.SymName(rs)
			}
			st.err.Errorf(s, "invalid relocation %s: %d+%d not in [%d,%d)", rname, off, siz, 0, len(P))
			continue
		}
		if siz == 0 { // informational relocation - no work to do
			continue
		}

		var rst sym.SymKind
		if rs != 0 {
			rst = ldr.SymType(rs)
		}

		if rs != 0 && (rst == sym.Sxxx || rst == sym.SXREF) {
			// When putting the runtime but not main into a shared library
			// these symbols are undefined and that's OK.
			if target.IsShared() || target.IsPlugin() {
				if ldr.SymName(rs) == "main.main" || (!target.IsPlugin() && ldr.SymName(rs) == "main..inittask") {
					sb := ldr.MakeSymbolUpdater(rs)
					sb.SetType(sym.SDYNIMPORT)
				} else if strings.HasPrefix(ldr.SymName(rs), "go:info.") {
					// Skip go.info symbols. They are only needed to communicate
					// DWARF info between the compiler and linker.
					continue
				}
			} else if target.IsPPC64() && ldr.SymName(rs) == ".TOC." {
				// TOC symbol doesn't have a type but we do assign a value
				// (see the address pass) and we can resolve it.
				// TODO: give it a type.
			} else {
				st.err.errorUnresolved(ldr, s, rs)
				continue
			}
		}

		if rt >= objabi.ElfRelocOffset {
			continue
		}

		// We need to be able to reference dynimport symbols when linking against
		// shared libraries, and AIX, Darwin, OpenBSD and Solaris always need it.
		if !target.IsAIX() && !target.IsDarwin() && !target.IsSolaris() && !target.IsOpenbsd() && rs != 0 && rst == sym.SDYNIMPORT && !target.IsDynlinkingGo() && !ldr.AttrSubSymbol(rs) {
			if !(target.IsPPC64() && target.IsExternal() && ldr.SymName(rs) == ".TOC.") {
				st.err.Errorf(s, "unhandled relocation for %s (type %d (%s) rtype %d (%s))", ldr.SymName(rs), rst, rst, rt, sym.RelocName(target.Arch, rt))
			}
		}
		if rs != 0 && rst != sym.STLSBSS && !weak && rt != objabi.R_METHODOFF && !ldr.AttrReachable(rs) {
			st.err.Errorf(s, "unreachable sym in relocation: %s", ldr.SymName(rs))
		}

		var rv sym.RelocVariant
		if target.IsPPC64() || target.IsS390X() {
			rv = ldr.RelocVariant(s, ri)
		}

		// TODO(mundaym): remove this special case - see issue 14218.
		if target.IsS390X() {
			switch rt {
			case objabi.R_PCRELDBL:
				rt = objabi.R_PCREL
				rv = sym.RV_390_DBL
			case objabi.R_CALL:
				rv = sym.RV_390_DBL
			}
		}

		var o int64
		switch rt {
		default:
			switch siz {
			default:
				st.err.Errorf(s, "bad reloc size %#x for %s", uint32(siz), ldr.SymName(rs))
			case 1:
				o = int64(P[off])
			case 2:
				o = int64(target.Arch.ByteOrder.Uint16(P[off:]))
			case 4:
				o = int64(target.Arch.ByteOrder.Uint32(P[off:]))
			case 8:
				o = int64(target.Arch.ByteOrder.Uint64(P[off:]))
			}
			out, n, ok := thearch.Archreloc(target, ldr, syms, r, s, o)
			if target.IsExternal() {
				nExtReloc += n
			}
			if ok {
				o = out
			} else {
				st.err.Errorf(s, "unknown reloc to %v: %d (%s)", ldr.SymName(rs), rt, sym.RelocName(target.Arch, rt))
			}
		case objabi.R_TLS_LE:
			if target.IsExternal() && target.IsElf() {
				nExtReloc++
				o = 0
				if !target.IsAMD64() {
					o = r.Add()
				}
				break
			}

			if target.IsElf() && target.IsARM() {
				// On ELF ARM, the thread pointer is 8 bytes before
				// the start of the thread-local data block, so add 8
				// to the actual TLS offset (r->sym->value).
				// This 8 seems to be a fundamental constant of
				// ELF on ARM (or maybe Glibc on ARM); it is not
				// related to the fact that our own TLS storage happens
				// to take up 8 bytes.
				o = 8 + ldr.SymValue(rs)
			} else if target.IsElf() || target.IsPlan9() || target.IsDarwin() {
				o = int64(syms.Tlsoffset) + r.Add()
			} else if target.IsWindows() {
				o = r.Add()
			} else {
				log.Fatalf("unexpected R_TLS_LE relocation for %v", target.HeadType)
			}
		case objabi.R_TLS_IE:
			if target.IsExternal() && target.IsElf() {
				nExtReloc++
				o = 0
				if !target.IsAMD64() {
					o = r.Add()
				}
				if target.Is386() {
					nExtReloc++ // need two ELF relocations on 386, see ../x86/asm.go:elfreloc1
				}
				break
			}
			if target.IsPIE() && target.IsElf() {
				// We are linking the final executable, so we
				// can optimize any TLS IE relocation to LE.
				if thearch.TLSIEtoLE == nil {
					log.Fatalf("internal linking of TLS IE not supported on %v", target.Arch.Family)
				}
				thearch.TLSIEtoLE(P, int(off), int(siz))
				o = int64(syms.Tlsoffset)
			} else {
				log.Fatalf("cannot handle R_TLS_IE (sym %s) when linking internally", ldr.SymName(s))
			}
		case objabi.R_ADDR, objabi.R_PEIMAGEOFF:
			if weak && !ldr.AttrReachable(rs) {
				// Redirect it to runtime.unreachableMethod, which will throw if called.
				rs = syms.unreachableMethod
			}
			if target.IsExternal() {
				nExtReloc++

				// set up addend for eventual relocation via outer symbol.
				rs := rs
				rs, off := FoldSubSymbolOffset(ldr, rs)
				xadd := r.Add() + off
				rst := ldr.SymType(rs)
				if rst != sym.SHOSTOBJ && rst != sym.SDYNIMPORT && rst != sym.SUNDEFEXT && ldr.SymSect(rs) == nil {
					st.err.Errorf(s, "missing section for relocation target %s", ldr.SymName(rs))
				}

				o = xadd
				if target.IsElf() {
					if target.IsAMD64() {
						o = 0
					}
				} else if target.IsDarwin() {
					if ldr.SymType(s).IsDWARF() {
						// We generally use symbol-targeted relocations.
						// DWARF tools seem to only handle section-targeted relocations,
						// so generate section-targeted relocations in DWARF sections.
						// See also machoreloc1.
						o += ldr.SymValue(rs)
					}
				} else if target.IsWindows() {
					// nothing to do
				} else if target.IsAIX() {
					o = ldr.SymValue(rs) + xadd
				} else {
					st.err.Errorf(s, "unhandled pcrel relocation to %s on %v", ldr.SymName(rs), target.HeadType)
				}

				break
			}

			// On AIX, a second relocation must be done by the loader,
			// as section addresses can change once loaded.
			// The "default" symbol address is still needed by the loader so
			// the current relocation can't be skipped.
			if target.IsAIX() && rst != sym.SDYNIMPORT {
				// It's not possible to make a loader relocation in a
				// symbol which is not inside .data section.
				// FIXME: It should be forbidden to have R_ADDR from a
				// symbol which isn't in .data. However, as .text has the
				// same address once loaded, this is possible.
				// TODO: .text (including rodata) to .data relocation
				// doesn't work correctly, so we should really disallow it.
				// See also aixStaticDataBase in symtab.go and in runtime.
				if ldr.SymSect(s).Seg == &Segdata {
					Xcoffadddynrel(target, ldr, syms, s, r, ri)
				}
			}

			o = ldr.SymValue(rs) + r.Add()
			if rt == objabi.R_PEIMAGEOFF {
				// The R_PEIMAGEOFF offset is a RVA, so subtract
				// the base address for the executable.
				o -= PEBASE
			}

			// On amd64, 4-byte offsets will be sign-extended, so it is impossible to
			// access more than 2GB of static data; fail at link time is better than
			// fail at runtime. See https://golang.org/issue/7980.
			// Instead of special casing only amd64, we treat this as an error on all
			// 64-bit architectures so as to be future-proof.
			if int32(o) < 0 && target.Arch.PtrSize > 4 && siz == 4 {
				st.err.Errorf(s, "non-pc-relative relocation address for %s is too big: %#x (%#x + %#x)", ldr.SymName(rs), uint64(o), ldr.SymValue(rs), r.Add())
				errorexit()
			}
		case objabi.R_DWARFSECREF:
			if ldr.SymSect(rs) == nil {
				st.err.Errorf(s, "missing DWARF section for relocation target %s", ldr.SymName(rs))
			}

			if target.IsExternal() {
				// On most platforms, the external linker needs to adjust DWARF references
				// as it combines DWARF sections. However, on Darwin, dsymutil does the
				// DWARF linking, and it understands how to follow section offsets.
				// Leaving in the relocation records confuses it (see
				// https://golang.org/issue/22068) so drop them for Darwin.
				if !target.IsDarwin() {
					nExtReloc++
				}

				xadd := r.Add() + ldr.SymValue(rs) - int64(ldr.SymSect(rs).Vaddr)

				o = xadd
				if target.IsElf() && target.IsAMD64() {
					o = 0
				}
				break
			}
			o = ldr.SymValue(rs) + r.Add() - int64(ldr.SymSect(rs).Vaddr)
		case objabi.R_METHODOFF:
			if !ldr.AttrReachable(rs) {
				// Set it to a sentinel value. The runtime knows this is not pointing to
				// anything valid.
				o = -1
				break
			}
			fallthrough
		case objabi.R_ADDROFF:
			if weak && !ldr.AttrReachable(rs) {
				continue
			}
			sect := ldr.SymSect(rs)
			if sect == nil {
				if rst == sym.SDYNIMPORT {
					st.err.Errorf(s, "cannot target DYNIMPORT sym in section-relative reloc: %s", ldr.SymName(rs))
				} else if rst == sym.SUNDEFEXT {
					st.err.Errorf(s, "undefined symbol in relocation: %s", ldr.SymName(rs))
				} else {
					st.err.Errorf(s, "missing section for relocation target %s", ldr.SymName(rs))
				}
				continue
			}

			// The method offset tables using this relocation expect the offset to be relative
			// to the start of the first text section, even if there are multiple.
			if sect.Name == ".text" {
				o = ldr.SymValue(rs) - int64(Segtext.Sections[0].Vaddr) + r.Add()
			} else {
				o = ldr.SymValue(rs) - int64(ldr.SymSect(rs).Vaddr) + r.Add()
			}

		case objabi.R_ADDRCUOFF:
			// debug_range and debug_loc elements use this relocation type to get an
			// offset from the start of the compile unit.
			o = ldr.SymValue(rs) + r.Add() - ldr.SymValue(loader.Sym(ldr.SymUnit(rs).Textp[0]))

		// r.Sym() can be 0 when CALL $(constant) is transformed from absolute PC to relative PC call.
		case objabi.R_GOTPCREL:
			if target.IsDynlinkingGo() && target.IsDarwin() && rs != 0 {
				nExtReloc++
				o = r.Add()
				break
			}
			if target.Is386() && target.IsExternal() && target.IsELF {
				nExtReloc++ // need two ELF relocations on 386, see ../x86/asm.go:elfreloc1
			}
			fallthrough
		case objabi.R_CALL, objabi.R_PCREL:
			if target.IsExternal() && rs != 0 && rst == sym.SUNDEFEXT {
				// pass through to the external linker.
				nExtReloc++
				o = 0
				break
			}
			if target.IsExternal() && rs != 0 && (ldr.SymSect(rs) != ldr.SymSect(s) || rt == objabi.R_GOTPCREL) {
				nExtReloc++

				// set up addend for eventual relocation via outer symbol.
				rs := rs
				rs, off := FoldSubSymbolOffset(ldr, rs)
				xadd := r.Add() + off - int64(siz) // relative to address after the relocated chunk
				rst := ldr.SymType(rs)
				if rst != sym.SHOSTOBJ && rst != sym.SDYNIMPORT && ldr.SymSect(rs) == nil {
					st.err.Errorf(s, "missing section for relocation target %s", ldr.SymName(rs))
				}

				o = xadd
				if target.IsElf() {
					if target.IsAMD64() {
						o = 0
					}
				} else if target.IsDarwin() {
					if rt == objabi.R_CALL {
						if target.IsExternal() && rst == sym.SDYNIMPORT {
							if target.IsAMD64() {
								// AMD64 dynamic relocations are relative to the end of the relocation.
								o += int64(siz)
							}
						} else {
							if rst != sym.SHOSTOBJ {
								o += int64(uint64(ldr.SymValue(rs)) - ldr.SymSect(rs).Vaddr)
							}
							o -= int64(off) // relative to section offset, not symbol
						}
					} else {
						o += int64(siz)
					}
				} else if target.IsWindows() && target.IsAMD64() { // only amd64 needs PCREL
					// PE/COFF's PC32 relocation uses the address after the relocated
					// bytes as the base. Compensate by skewing the addend.
					o += int64(siz)
				} else {
					st.err.Errorf(s, "unhandled pcrel relocation to %s on %v", ldr.SymName(rs), target.HeadType)
				}

				break
			}

			o = 0
			if rs != 0 {
				o = ldr.SymValue(rs)
			}

			o += r.Add() - (ldr.SymValue(s) + int64(off) + int64(siz))
		case objabi.R_SIZE:
			o = ldr.SymSize(rs) + r.Add()

		case objabi.R_XCOFFREF:
			if !target.IsAIX() {
				st.err.Errorf(s, "find XCOFF R_REF on non-XCOFF files")
			}
			if !target.IsExternal() {
				st.err.Errorf(s, "find XCOFF R_REF with internal linking")
			}
			nExtReloc++
			continue

		case objabi.R_DWARFFILEREF:
			// We don't renumber files in dwarf.go:writelines anymore.
			continue

		case objabi.R_CONST:
			o = r.Add()

		case objabi.R_GOTOFF:
			o = ldr.SymValue(rs) + r.Add() - ldr.SymValue(syms.GOT)
		}

		if target.IsPPC64() || target.IsS390X() {
			if rv != sym.RV_NONE {
				o = thearch.Archrelocvariant(target, ldr, r, rv, s, o, P)
			}
		}

		switch siz {
		default:
			st.err.Errorf(s, "bad reloc size %#x for %s", uint32(siz), ldr.SymName(rs))
		case 1:
			P[off] = byte(int8(o))
		case 2:
			if (rt == objabi.R_PCREL || rt == objabi.R_CALL) && o != int64(int16(o)) {
				st.err.Errorf(s, "pc-relative relocation address for %s is too big: %#x", ldr.SymName(rs), o)
			} else if o != int64(int16(o)) && o != int64(uint16(o)) {
				st.err.Errorf(s, "non-pc-relative relocation address for %s is too big: %#x", ldr.SymName(rs), uint64(o))
			}
			target.Arch.ByteOrder.PutUint16(P[off:], uint16(o))
		case 4:
			if (rt == objabi.R_PCREL || rt == objabi.R_CALL) && o != int64(int32(o)) {
				st.err.Errorf(s, "pc-relative relocation address for %s is too big: %#x", ldr.SymName(rs), o)
			} else if o != int64(int32(o)) && o != int64(uint32(o)) {
				st.err.Errorf(s, "non-pc-relative relocation address for %s is too big: %#x", ldr.SymName(rs), uint64(o))
			}
			target.Arch.ByteOrder.PutUint32(P[off:], uint32(o))
		case 8:
			target.Arch.ByteOrder.PutUint64(P[off:], uint64(o))
		}
	}
	if target.IsExternal() {
		// We'll stream out the external relocations in asmb2 (e.g. elfrelocsect)
		// and we only need the count here.
		atomic.AddUint32(&ldr.SymSect(s).Relcount, uint32(nExtReloc))
	}
}

// Convert a Go relocation to an external relocation.
func extreloc(ctxt *Link, ldr *loader.Loader, s loader.Sym, r loader.Reloc) (loader.ExtReloc, bool) {
	var rr loader.ExtReloc
	target := &ctxt.Target
	siz := int32(r.Siz())
	if siz == 0 { // informational relocation - no work to do
		return rr, false
	}

	rt := r.Type()
	if rt >= objabi.ElfRelocOffset {
		return rr, false
	}
	rr.Type = rt
	rr.Size = uint8(siz)

	// TODO(mundaym): remove this special case - see issue 14218.
	if target.IsS390X() {
		switch rt {
		case objabi.R_PCRELDBL:
			rt = objabi.R_PCREL
		}
	}

	switch rt {
	default:
		return thearch.Extreloc(target, ldr, r, s)

	case objabi.R_TLS_LE, objabi.R_TLS_IE:
		if target.IsElf() {
			rs := r.Sym()
			rr.Xsym = rs
			if rr.Xsym == 0 {
				rr.Xsym = ctxt.Tlsg
			}
			rr.Xadd = r.Add()
			break
		}
		return rr, false

	case objabi.R_ADDR, objabi.R_PEIMAGEOFF:
		// set up addend for eventual relocation via outer symbol.
		rs := r.Sym()
		if r.Weak() && !ldr.AttrReachable(rs) {
			rs = ctxt.ArchSyms.unreachableMethod
		}
		rs, off := FoldSubSymbolOffset(ldr, rs)
		rr.Xadd = r.Add() + off
		rr.Xsym = rs

	case objabi.R_DWARFSECREF:
		// On most platforms, the external linker needs to adjust DWARF references
		// as it combines DWARF sections. However, on Darwin, dsymutil does the
		// DWARF linking, and it understands how to follow section offsets.
		// Leaving in the relocation records confuses it (see
		// https://golang.org/issue/22068) so drop them for Darwin.
		if target.IsDarwin() {
			return rr, false
		}
		rs := r.Sym()
		rr.Xsym = loader.Sym(ldr.SymSect(rs).Sym)
		rr.Xadd = r.Add() + ldr.SymValue(rs) - int64(ldr.SymSect(rs).Vaddr)

	// r.Sym() can be 0 when CALL $(constant) is transformed from absolute PC to relative PC call.
	case objabi.R_GOTPCREL, objabi.R_CALL, objabi.R_PCREL:
		rs := r.Sym()
		if rt == objabi.R_GOTPCREL && target.IsDynlinkingGo() && target.IsDarwin() && rs != 0 {
			rr.Xadd = r.Add()
			rr.Xadd -= int64(siz) // relative to address after the relocated chunk
			rr.Xsym = rs
			break
		}
		if rs != 0 && ldr.SymType(rs) == sym.SUNDEFEXT {
			// pass through to the external linker.
			rr.Xadd = 0
			if target.IsElf() {
				rr.Xadd -= int64(siz)
			}
			rr.Xsym = rs
			break
		}
		if rs != 0 && (ldr.SymSect(rs) != ldr.SymSect(s) || rt == objabi.R_GOTPCREL) {
			// set up addend for eventual relocation via outer symbol.
			rs := rs
			rs, off := FoldSubSymbolOffset(ldr, rs)
			rr.Xadd = r.Add() + off
			rr.Xadd -= int64(siz) // relative to address after the relocated chunk
			rr.Xsym = rs
			break
		}
		return rr, false

	case objabi.R_XCOFFREF:
		return ExtrelocSimple(ldr, r), true

	// These reloc types don't need external relocations.
	case objabi.R_ADDROFF, objabi.R_METHODOFF, objabi.R_ADDRCUOFF,
		objabi.R_SIZE, objabi.R_CONST, objabi.R_GOTOFF:
		return rr, false
	}
	return rr, true
}

// ExtrelocSimple creates a simple external relocation from r, with the same
// symbol and addend.
func ExtrelocSimple(ldr *loader.Loader, r loader.Reloc) loader.ExtReloc {
	var rr loader.ExtReloc
	rs := r.Sym()
	rr.Xsym = rs
	rr.Xadd = r.Add()
	rr.Type = r.Type()
	rr.Size = r.Siz()
	return rr
}

// ExtrelocViaOuterSym creates an external relocation from r targeting the
// outer symbol and folding the subsymbol's offset into the addend.
func ExtrelocViaOuterSym(ldr *loader.Loader, r loader.Reloc, s loader.Sym) loader.ExtReloc {
	// set up addend for eventual relocation via outer symbol.
	var rr loader.ExtReloc
	rs := r.Sym()
	rs, off := FoldSubSymbolOffset(ldr, rs)
	rr.Xadd = r.Add() + off
	rst := ldr.SymType(rs)
	if rst != sym.SHOSTOBJ && rst != sym.SDYNIMPORT && rst != sym.SUNDEFEXT && ldr.SymSect(rs) == nil {
		ldr.Errorf(s, "missing section for %s", ldr.SymName(rs))
	}
	rr.Xsym = rs
	rr.Type = r.Type()
	rr.Size = r.Siz()
	return rr
}

// relocSymState hold state information needed when making a series of
// successive calls to relocsym(). The items here are invariant
// (meaning that they are set up once initially and then don't change
// during the execution of relocsym), with the exception of a slice
// used to facilitate batch allocation of external relocations. Calls
// to relocsym happen in parallel; the assumption is that each
// parallel thread will have its own state object.
type relocSymState struct {
	target *Target
	ldr    *loader.Loader
	err    *ErrorReporter
	syms   *ArchSyms
}

// makeRelocSymState creates a relocSymState container object to
// pass to relocsym(). If relocsym() calls happen in parallel,
// each parallel thread should have its own state object.
func (ctxt *Link) makeRelocSymState() *relocSymState {
	return &relocSymState{
		target: &ctxt.Target,
		ldr:    ctxt.loader,
		err:    &ctxt.ErrorReporter,
		syms:   &ctxt.ArchSyms,
	}
}

// windynrelocsym examines a text symbol 's' and looks for relocations
// from it that correspond to references to symbols defined in DLLs,
// then fixes up those relocations as needed. A reference to a symbol
// XYZ from some DLL will fall into one of two categories: an indirect
// ref via "__imp_XYZ", or a direct ref to "XYZ". Here's an example of
// an indirect ref (this is an excerpt from objdump -ldr):
//
//	     1c1: 48 89 c6                     	movq	%rax, %rsi
//	     1c4: ff 15 00 00 00 00            	callq	*(%rip)
//			00000000000001c6:  IMAGE_REL_AMD64_REL32	__imp__errno
//
// In the assembly above, the code loads up the value of __imp_errno
// and then does an indirect call to that value.
//
// Here is what a direct reference might look like:
//
//	     137: e9 20 06 00 00               	jmp	0x75c <pow+0x75c>
//	     13c: e8 00 00 00 00               	callq	0x141 <pow+0x141>
//			000000000000013d:  IMAGE_REL_AMD64_REL32	_errno
//
// The assembly below dispenses with the import symbol and just makes
// a direct call to _errno.
//
// The code below handles indirect refs by redirecting the target of
// the relocation from "__imp_XYZ" to "XYZ" (since the latter symbol
// is what the Windows loader is expected to resolve). For direct refs
// the call is redirected to a stub, where the stub first loads the
// symbol and then direct an indirect call to that value.
//
// Note that for a given symbol (as above) it is perfectly legal to
// have both direct and indirect references.
func windynrelocsym(ctxt *Link, rel *loader.SymbolBuilder, s loader.Sym) error {
	var su *loader.SymbolBuilder
	relocs := ctxt.loader.Relocs(s)
	for ri := 0; ri < relocs.Count(); ri++ {
		r := relocs.At(ri)
		if r.IsMarker() {
			continue // skip marker relocations
		}
		targ := r.Sym()
		if targ == 0 {
			continue
		}
		if !ctxt.loader.AttrReachable(targ) {
			if r.Weak() {
				continue
			}
			return fmt.Errorf("dynamic relocation to unreachable symbol %s",
				ctxt.loader.SymName(targ))
		}
		tgot := ctxt.loader.SymGot(targ)
		if tgot == loadpe.RedirectToDynImportGotToken {

			// Consistency check: name should be __imp_X
			sname := ctxt.loader.SymName(targ)
			if !strings.HasPrefix(sname, "__imp_") {
				return fmt.Errorf("internal error in windynrelocsym: redirect GOT token applied to non-import symbol %s", sname)
			}

			// Locate underlying symbol (which originally had type
			// SDYNIMPORT but has since been retyped to SWINDOWS).
			ds, err := loadpe.LookupBaseFromImport(targ, ctxt.loader, ctxt.Arch)
			if err != nil {
				return err
			}
			dstyp := ctxt.loader.SymType(ds)
			if dstyp != sym.SWINDOWS {
				return fmt.Errorf("internal error in windynrelocsym: underlying sym for %q has wrong type %s", sname, dstyp.String())
			}

			// Redirect relocation to the dynimport.
			r.SetSym(ds)
			continue
		}

		tplt := ctxt.loader.SymPlt(targ)
		if tplt == loadpe.CreateImportStubPltToken {

			// Consistency check: don't want to see both PLT and GOT tokens.
			if tgot != -1 {
				return fmt.Errorf("internal error in windynrelocsym: invalid GOT setting %d for reloc to %s", tgot, ctxt.loader.SymName(targ))
			}

			// make dynimport JMP table for PE object files.
			tplt := int32(rel.Size())
			ctxt.loader.SetPlt(targ, tplt)

			if su == nil {
				su = ctxt.loader.MakeSymbolUpdater(s)
			}
			r.SetSym(rel.Sym())
			r.SetAdd(int64(tplt))

			// jmp *addr
			switch ctxt.Arch.Family {
			default:
				return fmt.Errorf("internal error in windynrelocsym: unsupported arch %v", ctxt.Arch.Family)
			case sys.I386:
				rel.AddUint8(0xff)
				rel.AddUint8(0x25)
				rel.AddAddrPlus(ctxt.Arch, targ, 0)
				rel.AddUint8(0x90)
				rel.AddUint8(0x90)
			case sys.AMD64:
				rel.AddUint8(0xff)
				rel.AddUint8(0x24)
				rel.AddUint8(0x25)
				rel.AddAddrPlus4(ctxt.Arch, targ, 0)
				rel.AddUint8(0x90)
			}
		} else if tplt >= 0 {
			if su == nil {
				su = ctxt.loader.MakeSymbolUpdater(s)
			}
			r.SetSym(rel.Sym())
			r.SetAdd(int64(tplt))
		}
	}
	return nil
}

// windynrelocsyms generates jump table to C library functions that will be
// added later. windynrelocsyms writes the table into .rel symbol.
func (ctxt *Link) windynrelocsyms() {
	if !(ctxt.IsWindows() && iscgo && ctxt.IsInternal()) {
		return
	}

	rel := ctxt.loader.CreateSymForUpdate(".rel", 0)
	rel.SetType(sym.STEXT)

	for _, s := range ctxt.Textp {
		if err := windynrelocsym(ctxt, rel, s); err != nil {
			ctxt.Errorf(s, "%v", err)
		}
	}

	ctxt.Textp = append(ctxt.Textp, rel.Sym())
}

func dynrelocsym(ctxt *Link, s loader.Sym) {
	target := &ctxt.Target
	ldr := ctxt.loader
	syms := &ctxt.ArchSyms
	relocs := ldr.Relocs(s)
	for ri := 0; ri < relocs.Count(); ri++ {
		r := relocs.At(ri)
		if r.IsMarker() {
			continue // skip marker relocations
		}
		rSym := r.Sym()
		if r.Weak() && !ldr.AttrReachable(rSym) {
			continue
		}
		if ctxt.BuildMode == BuildModePIE && ctxt.LinkMode == LinkInternal {
			// It's expected that some relocations will be done
			// later by relocsym (R_TLS_LE, R_ADDROFF), so
			// don't worry if Adddynrel returns false.
			thearch.Adddynrel(target, ldr, syms, s, r, ri)
			continue
		}

		if rSym != 0 && ldr.SymType(rSym) == sym.SDYNIMPORT || r.Type() >= objabi.ElfRelocOffset {
			if rSym != 0 && !ldr.AttrReachable(rSym) {
				ctxt.Errorf(s, "dynamic relocation to unreachable symbol %s", ldr.SymName(rSym))
			}
			if !thearch.Adddynrel(target, ldr, syms, s, r, ri) {
				ctxt.Errorf(s, "unsupported dynamic relocation for symbol %s (type=%d (%s) stype=%d (%s))", ldr.SymName(rSym), r.Type(), sym.RelocName(ctxt.Arch, r.Type()), ldr.SymType(rSym), ldr.SymType(rSym))
			}
		}
	}
}

func (state *dodataState) dynreloc(ctxt *Link) {
	if ctxt.HeadType == objabi.Hwindows {
		return
	}
	// -d suppresses dynamic loader format, so we may as well not
	// compute these sections or mark their symbols as reachable.
	if *FlagD {
		return
	}

	for _, s := range ctxt.Textp {
		dynrelocsym(ctxt, s)
	}
	for _, syms := range state.data {
		for _, s := range syms {
			dynrelocsym(ctxt, s)
		}
	}
	if ctxt.IsELF {
		elfdynhash(ctxt)
	}
}

func CodeblkPad(ctxt *Link, out *OutBuf, addr int64, size int64, pad []byte) {
	writeBlocks(ctxt, out, ctxt.outSem, ctxt.loader, ctxt.Textp, addr, size, pad)
}

const blockSize = 1 << 20 // 1MB chunks written at a time.

// writeBlocks writes a specified chunk of symbols to the output buffer. It
// breaks the write up into ≥blockSize chunks to write them out, and schedules
// as many goroutines as necessary to accomplish this task. This call then
// blocks, waiting on the writes to complete. Note that we use the sem parameter
// to limit the number of concurrent writes taking place.
func writeBlocks(ctxt *Link, out *OutBuf, sem chan int, ldr *loader.Loader, syms []loader.Sym, addr, size int64, pad []byte) {
	for i, s := range syms {
		if ldr.SymValue(s) >= addr && !ldr.AttrSubSymbol(s) {
			syms = syms[i:]
			break
		}
	}

	var wg sync.WaitGroup
	max, lastAddr, written := int64(blockSize), addr+size, int64(0)
	for addr < lastAddr {
		// Find the last symbol we'd write.
		idx := -1
		for i, s := range syms {
			if ldr.AttrSubSymbol(s) {
				continue
			}

			// If the next symbol's size would put us out of bounds on the total length,
			// stop looking.
			end := ldr.SymValue(s) + ldr.SymSize(s)
			if end > lastAddr {
				break
			}

			// We're gonna write this symbol.
			idx = i

			// If we cross over the max size, we've got enough symbols.
			if end > addr+max {
				break
			}
		}

		// If we didn't find any symbols to write, we're done here.
		if idx < 0 {
			break
		}

		// Compute the length to write, including padding.
		// We need to write to the end address (lastAddr), or the next symbol's
		// start address, whichever comes first. If there is no more symbols,
		// just write to lastAddr. This ensures we don't leave holes between the
		// blocks or at the end.
		length := int64(0)
		if idx+1 < len(syms) {
			// Find the next top-level symbol.
			// Skip over sub symbols so we won't split a container symbol
			// into two blocks.
			next := syms[idx+1]
			for ldr.AttrSubSymbol(next) {
				idx++
				next = syms[idx+1]
			}
			length = ldr.SymValue(next) - addr
		}
		if length == 0 || length > lastAddr-addr {
			length = lastAddr - addr
		}

		// Start the block output operator.
		if o, err := out.View(uint64(out.Offset() + written)); err == nil {
			sem <- 1
			wg.Add(1)
			go func(o *OutBuf, ldr *loader.Loader, syms []loader.Sym, addr, size int64, pad []byte) {
				writeBlock(ctxt, o, ldr, syms, addr, size, pad)
				wg.Done()
				<-sem
			}(o, ldr, syms, addr, length, pad)
		} else { // output not mmaped, don't parallelize.
			writeBlock(ctxt, out, ldr, syms, addr, length, pad)
		}

		// Prepare for the next loop.
		if idx != -1 {
			syms = syms[idx+1:]
		}
		written += length
		addr += length
	}
	wg.Wait()
}

func writeBlock(ctxt *Link, out *OutBuf, ldr *loader.Loader, syms []loader.Sym, addr, size int64, pad []byte) {

	st := ctxt.makeRelocSymState()

	// This doesn't distinguish the memory size from the file
	// size, and it lays out the file based on Symbol.Value, which
	// is the virtual address. DWARF compression changes file sizes,
	// so dwarfcompress will fix this up later if necessary.
	eaddr := addr + size
	var prev loader.Sym
	for _, s := range syms {
		if ldr.AttrSubSymbol(s) {
			continue
		}
		val := ldr.SymValue(s)
		if val >= eaddr {
			break
		}
		if val < addr {
			ldr.Errorf(s, "phase error: addr=%#x but val=%#x sym=%s type=%v sect=%v sect.addr=%#x prev=%s", addr, val, ldr.SymName(s), ldr.SymType(s), ldr.SymSect(s).Name, ldr.SymSect(s).Vaddr, ldr.SymName(prev))
			errorexit()
		}
		prev = s
		if addr < val {
			out.WriteStringPad("", int(val-addr), pad)
			addr = val
		}
		P := out.WriteSym(ldr, s)
		st.relocsym(s, P)
		if ldr.IsGeneratedSym(s) {
			f := ctxt.generatorSyms[s]
			f(ctxt, s)
		}
		addr += int64(len(P))
		siz := ldr.SymSize(s)
		if addr < val+siz {
			out.WriteStringPad("", int(val+siz-addr), pad)
			addr = val + siz
		}
		if addr != val+siz {
			ldr.Errorf(s, "phase error: addr=%#x value+size=%#x", addr, val+siz)
			errorexit()
		}
		if val+siz >= eaddr {
			break
		}
	}

	if addr < eaddr {
		out.WriteStringPad("", int(eaddr-addr), pad)
	}
}

type writeFn func(*Link, *OutBuf, int64, int64)

// writeParallel handles scheduling parallel execution of data write functions.
func writeParallel(wg *sync.WaitGroup, fn writeFn, ctxt *Link, seek, vaddr, length uint64) {
	if out, err := ctxt.Out.View(seek); err != nil {
		ctxt.Out.SeekSet(int64(seek))
		fn(ctxt, ctxt.Out, int64(vaddr), int64(length))
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()
			fn(ctxt, out, int64(vaddr), int64(length))
		}()
	}
}

func datblk(ctxt *Link, out *OutBuf, addr, size int64) {
	writeDatblkToOutBuf(ctxt, out, addr, size)
}

// Used only on Wasm for now.
func DatblkBytes(ctxt *Link, addr int64, size int64) []byte {
	buf := make([]byte, size)
	out := &OutBuf{heap: buf}
	writeDatblkToOutBuf(ctxt, out, addr, size)
	return buf
}

func writeDatblkToOutBuf(ctxt *Link, out *OutBuf, addr int64, size int64) {
	writeBlocks(ctxt, out, ctxt.outSem, ctxt.loader, ctxt.datap, addr, size, zeros[:])
}

func dwarfblk(ctxt *Link, out *OutBuf, addr int64, size int64) {
	// Concatenate the section symbol lists into a single list to pass
	// to writeBlocks.
	//
	// NB: ideally we would do a separate writeBlocks call for each
	// section, but this would run the risk of undoing any file offset
	// adjustments made during layout.
	n := 0
	for i := range dwarfp {
		n += len(dwarfp[i].syms)
	}
	syms := make([]loader.Sym, 0, n)
	for i := range dwarfp {
		syms = append(syms, dwarfp[i].syms...)
	}
	writeBlocks(ctxt, out, ctxt.outSem, ctxt.loader, syms, addr, size, zeros[:])
}

func pdatablk(ctxt *Link, out *OutBuf, addr int64, size int64) {
	writeBlocks(ctxt, out, ctxt.outSem, ctxt.loader, sehp.pdata, addr, size, zeros[:])
}

func xdatablk(ctxt *Link, out *OutBuf, addr int64, size int64) {
	writeBlocks(ctxt, out, ctxt.outSem, ctxt.loader, sehp.xdata, addr, size, zeros[:])
}

var covCounterDataStartOff, covCounterDataLen uint64

var zeros [512]byte

var (
	strdata  = make(map[string]string)
	strnames []string
)

func addstrdata1(ctxt *Link, arg string) {
	eq := strings.Index(arg, "=")
	dot := strings.LastIndex(arg[:eq+1], ".")
	if eq < 0 || dot < 0 {
		Exitf("-X flag requires argument of the form importpath.name=value")
	}
	pkg := arg[:dot]
	if ctxt.BuildMode == BuildModePlugin && pkg == "main" {
		pkg = *flagPluginPath
	}
	pkg = objabi.PathToPrefix(pkg)
	name := pkg + arg[dot:eq]
	value := arg[eq+1:]
	if _, ok := strdata[name]; !ok {
		strnames = append(strnames, name)
	}
	strdata[name] = value
}

// addstrdata sets the initial value of the string variable name to value.
func addstrdata(arch *sys.Arch, l *loader.Loader, name, value string) {
	s := l.Lookup(name, 0)
	if s == 0 {
		return
	}
	if goType := l.SymGoType(s); goType == 0 {
		return
	} else if typeName := l.SymName(goType); typeName != "type:string" {
		Errorf("%s: cannot set with -X: not a var of type string (%s)", name, typeName)
		return
	}
	if !l.AttrReachable(s) {
		return // don't bother setting unreachable variable
	}
	bld := l.MakeSymbolUpdater(s)
	if bld.Type() == sym.SBSS {
		bld.SetType(sym.SDATA)
	}

	p := fmt.Sprintf("%s.str", name)
	sbld := l.CreateSymForUpdate(p, 0)
	sbld.Addstring(value)
	sbld.SetType(sym.SRODATA)

	// Don't reset the variable's size. String variable usually has size of
	// 2*PtrSize, but in ASAN build it can be larger due to red zone.
	// (See issue 56175.)
	bld.SetData(make([]byte, arch.PtrSize*2))
	bld.SetReadOnly(false)
	bld.ResetRelocs()
	bld.SetAddrPlus(arch, 0, sbld.Sym(), 0)
	bld.SetUint(arch, int64(arch.PtrSize), uint64(len(value)))
}

func (ctxt *Link) dostrdata() {
	for _, name := range strnames {
		addstrdata(ctxt.Arch, ctxt.loader, name, strdata[name])
	}
}

// addgostring adds str, as a Go string value, to s. symname is the name of the
// symbol used to define the string data and must be unique per linked object.
func addgostring(ctxt *Link, ldr *loader.Loader, s *loader.SymbolBuilder, symname, str string) {
	sdata := ldr.CreateSymForUpdate(symname, 0)
	if sdata.Type() != sym.Sxxx {
		ctxt.Errorf(s.Sym(), "duplicate symname in addgostring: %s", symname)
	}
	sdata.SetLocal(true)
	sdata.SetType(sym.SRODATA)
	sdata.SetSize(int64(len(str)))
	sdata.SetData([]byte(str))
	s.AddAddr(ctxt.Arch, sdata.Sym())
	s.AddUint(ctxt.Arch, uint64(len(str)))
}

func addinitarrdata(ctxt *Link, ldr *loader.Loader, s loader.Sym) {
	p := ldr.SymName(s) + ".ptr"
	sp := ldr.CreateSymForUpdate(p, 0)
	sp.SetType(sym.SINITARR)
	sp.SetSize(0)
	sp.SetDuplicateOK(true)
	sp.AddAddr(ctxt.Arch, s)
}

// symalign returns the required alignment for the given symbol s.
func symalign(ldr *loader.Loader, s loader.Sym) int32 {
	min := int32(thearch.Minalign)
	align := ldr.SymAlign(s)
	if align >= min {
		return align
	} else if align != 0 {
		return min
	}
	align = int32(thearch.Maxalign)
	ssz := ldr.SymSize(s)
	for int64(align) > ssz && align > min {
		align >>= 1
	}
	ldr.SetSymAlign(s, align)
	return align
}

func aligndatsize(state *dodataState, datsize int64, s loader.Sym) int64 {
	return Rnd(datsize, int64(symalign(state.ctxt.loader, s)))
}

const debugGCProg = false

type GCProg struct {
	ctxt *Link
	sym  *loader.SymbolBuilder
	w    gcprog.Writer
}

func (p *GCProg) Init(ctxt *Link, name string) {
	p.ctxt = ctxt
	p.sym = ctxt.loader.CreateSymForUpdate(name, 0)
	p.w.Init(p.writeByte())
	if debugGCProg {
		fmt.Fprintf(os.Stderr, "ld: start GCProg %s\n", name)
		p.w.Debug(os.Stderr)
	}
}

func (p *GCProg) writeByte() func(x byte) {
	return func(x byte) {
		p.sym.AddUint8(x)
	}
}

func (p *GCProg) End(size int64) {
	p.w.ZeroUntil(size / int64(p.ctxt.Arch.PtrSize))
	p.w.End()
	if debugGCProg {
		fmt.Fprintf(os.Stderr, "ld: end GCProg\n")
	}
}

func (p *GCProg) AddSym(s loader.Sym) {
	ldr := p.ctxt.loader
	typ := ldr.SymGoType(s)

	// Things without pointers should be in sym.SNOPTRDATA or sym.SNOPTRBSS;
	// everything we see should have pointers and should therefore have a type.
	if typ == 0 {
		switch ldr.SymName(s) {
		case "runtime.data", "runtime.edata", "runtime.bss", "runtime.ebss", "runtime.gcdata", "runtime.gcbss":
			// Ignore special symbols that are sometimes laid out
			// as real symbols. See comment about dyld on darwin in
			// the address function.
			return
		}
		p.ctxt.Errorf(p.sym.Sym(), "missing Go type information for global symbol %s: size %d", ldr.SymName(s), ldr.SymSize(s))
		return
	}

	if debugGCProg {
		fmt.Fprintf(os.Stderr, "gcprog sym: %s at %d (ptr=%d)\n", ldr.SymName(s), ldr.SymValue(s), ldr.SymValue(s)/int64(p.ctxt.Arch.PtrSize))
	}

	sval := ldr.SymValue(s)
	p.AddType(sval, typ)
}

// Add to the gc program the ptr bits for the type typ at
// byte offset off in the region being described.
// The type must have a pointer in it.
func (p *GCProg) AddType(off int64, typ loader.Sym) {
	ldr := p.ctxt.loader
	typData := ldr.Data(typ)
	ptrdata := decodetypePtrdata(p.ctxt.Arch, typData)
	if ptrdata == 0 {
		p.ctxt.Errorf(p.sym.Sym(), "has no pointers but in data section")
		// TODO: just skip these? They might occur in assembly
		// that doesn't know to use NOPTR? But there must have been
		// a Go declaration somewhere.
	}
	switch decodetypeKind(p.ctxt.Arch, typData) {
	default:
		if decodetypeGCMaskOnDemand(p.ctxt.Arch, typData) {
			p.ctxt.Errorf(p.sym.Sym(), "GC mask not available")
		}
		// Copy pointers from mask into program.
		ptrsize := int64(p.ctxt.Arch.PtrSize)
		mask := decodetypeGcmask(p.ctxt, typ)
		for i := int64(0); i < ptrdata/ptrsize; i++ {
			if (mask[i/8]>>uint(i%8))&1 != 0 {
				p.w.Ptr(off/ptrsize + i)
			}
		}
	case abi.Array:
		elem := decodetypeArrayElem(p.ctxt, p.ctxt.Arch, typ)
		n := decodetypeArrayLen(ldr, p.ctxt.Arch, typ)
		p.AddType(off, elem)
		if n > 1 {
			// Issue repeat for subsequent n-1 instances.
			elemSize := decodetypeSize(p.ctxt.Arch, ldr.Data(elem))
			ptrsize := int64(p.ctxt.Arch.PtrSize)
			p.w.ZeroUntil((off + elemSize) / ptrsize)
			p.w.Repeat(elemSize/ptrsize, n-1)
		}
	case abi.Struct:
		nField := decodetypeStructFieldCount(ldr, p.ctxt.Arch, typ)
		for i := 0; i < nField; i++ {
			fTyp := decodetypeStructFieldType(p.ctxt, p.ctxt.Arch, typ, i)
			if decodetypePtrdata(p.ctxt.Arch, ldr.Data(fTyp)) == 0 {
				continue
			}
			fOff := decodetypeStructFieldOffset(ldr, p.ctxt.Arch, typ, i)
			p.AddType(off+fOff, fTyp)
		}
	}
}

// cutoff is the maximum data section size permitted by the linker
// (see issue #9862).
const cutoff = 2e9 // 2 GB (or so; looks better in errors than 2^31)

// check accumulated size of data sections
func (state *dodataState) checkdatsize(symn sym.SymKind) {
	if state.datsize > cutoff {
		Errorf("too much data, last section %v (%d, over %v bytes)", symn, state.datsize, cutoff)
	}
}

func checkSectSize(sect *sym.Section) {
	// TODO: consider using 4 GB size limit for DWARF sections, and
	// make sure we generate unsigned offset in relocations and check
	// for overflow.
	if sect.Length > cutoff {
		Errorf("too much data in section %s (%d, over %v bytes)", sect.Name, sect.Length, cutoff)
	}
}

// fixZeroSizedSymbols gives a few special symbols with zero size some space.
func fixZeroSizedSymbols(ctxt *Link) {
	// The values in moduledata are filled out by relocations
	// pointing to the addresses of these special symbols.
	// Typically these symbols have no size and are not laid
	// out with their matching section.
	//
	// However on darwin, dyld will find the special symbol
	// in the first loaded module, even though it is local.
	//
	// (An hypothesis, formed without looking in the dyld sources:
	// these special symbols have no size, so their address
	// matches a real symbol. The dynamic linker assumes we
	// want the normal symbol with the same address and finds
	// it in the other module.)
	//
	// To work around this we lay out the symbls whose
	// addresses are vital for multi-module programs to work
	// as normal symbols, and give them a little size.
	//
	// On AIX, as all DATA sections are merged together, ld might not put
	// these symbols at the beginning of their respective section if there
	// aren't real symbols, their alignment might not match the
	// first symbol alignment. Therefore, there are explicitly put at the
	// beginning of their section with the same alignment.
	if !(ctxt.DynlinkingGo() && ctxt.HeadType == objabi.Hdarwin) && !(ctxt.HeadType == objabi.Haix && ctxt.LinkMode == LinkExternal) {
		return
	}

	ldr := ctxt.loader
	bss := ldr.CreateSymForUpdate("runtime.bss", 0)
	bss.SetSize(8)
	ldr.SetAttrSpecial(bss.Sym(), false)

	ebss := ldr.CreateSymForUpdate("runtime.ebss", 0)
	ldr.SetAttrSpecial(ebss.Sym(), false)

	data := ldr.CreateSymForUpdate("runtime.data", 0)
	data.SetSize(8)
	ldr.SetAttrSpecial(data.Sym(), false)

	edata := ldr.CreateSymForUpdate("runtime.edata", 0)
	ldr.SetAttrSpecial(edata.Sym(), false)

	if ctxt.HeadType == objabi.Haix {
		// XCOFFTOC symbols are part of .data section.
		edata.SetType(sym.SXCOFFTOC)
	}

	noptrbss := ldr.CreateSymForUpdate("runtime.noptrbss", 0)
	noptrbss.SetSize(8)
	ldr.SetAttrSpecial(noptrbss.Sym(), false)

	enoptrbss := ldr.CreateSymForUpdate("runtime.enoptrbss", 0)
	ldr.SetAttrSpecial(enoptrbss.Sym(), false)

	noptrdata := ldr.CreateSymForUpdate("runtime.noptrdata", 0)
	noptrdata.SetSize(8)
	ldr.SetAttrSpecial(noptrdata.Sym(), false)

	enoptrdata := ldr.CreateSymForUpdate("runtime.enoptrdata", 0)
	ldr.SetAttrSpecial(enoptrdata.Sym(), false)

	types := ldr.CreateSymForUpdate("runtime.types", 0)
	types.SetType(sym.STYPE)
	types.SetSize(8)
	ldr.SetAttrSpecial(types.Sym(), false)

	etypes := ldr.CreateSymForUpdate("runtime.etypes", 0)
	etypes.SetType(sym.SFUNCTAB)
	ldr.SetAttrSpecial(etypes.Sym(), false)

	if ctxt.HeadType == objabi.Haix {
		rodata := ldr.CreateSymForUpdate("runtime.rodata", 0)
		rodata.SetType(sym.SSTRING)
		rodata.SetSize(8)
		ldr.SetAttrSpecial(rodata.Sym(), false)

		erodata := ldr.CreateSymForUpdate("runtime.erodata", 0)
		ldr.SetAttrSpecial(erodata.Sym(), false)
	}
}

// makeRelroForSharedLib creates a section of readonly data if necessary.
func (state *dodataState) makeRelroForSharedLib(target *Link) {
	if !target.UseRelro() {
		return
	}

	// "read only" data with relocations needs to go in its own section
	// when building a shared library. We do this by boosting objects of
	// type SXXX with relocations to type SXXXRELRO.
	ldr := target.loader
	for _, symnro := range sym.ReadOnly {
		symnrelro := sym.RelROMap[symnro]

		ro := []loader.Sym{}
		relro := state.data[symnrelro]

		for _, s := range state.data[symnro] {
			relocs := ldr.Relocs(s)
			isRelro := relocs.Count() > 0
			switch state.symType(s) {
			case sym.STYPE, sym.STYPERELRO, sym.SGOFUNCRELRO:
				// Symbols are not sorted yet, so it is possible
				// that an Outer symbol has been changed to a
				// relro Type before it reaches here.
				isRelro = true
			case sym.SFUNCTAB:
				if ldr.SymName(s) == "runtime.etypes" {
					// runtime.etypes must be at the end of
					// the relro data.
					isRelro = true
				}
			case sym.SGOFUNC:
				// The only SGOFUNC symbols that contain relocations are .stkobj,
				// and their relocations are of type objabi.R_ADDROFF,
				// which always get resolved during linking.
				isRelro = false
			}
			if isRelro {
				if symnrelro == sym.Sxxx {
					state.ctxt.Errorf(s, "cannot contain relocations (type %v)", symnro)
				}
				state.setSymType(s, symnrelro)
				if outer := ldr.OuterSym(s); outer != 0 {
					state.setSymType(outer, symnrelro)
				}
				relro = append(relro, s)
			} else {
				ro = append(ro, s)
			}
		}

		// Check that we haven't made two symbols with the same .Outer into
		// different types (because references two symbols with non-nil Outer
		// become references to the outer symbol + offset it's vital that the
		// symbol and the outer end up in the same section).
		for _, s := range relro {
			if outer := ldr.OuterSym(s); outer != 0 {
				st := state.symType(s)
				ost := state.symType(outer)
				if st != ost {
					state.ctxt.Errorf(s, "inconsistent types for symbol and its Outer %s (%v != %v)",
						ldr.SymName(outer), st, ost)
				}
			}
		}

		state.data[symnro] = ro
		state.data[symnrelro] = relro
	}
}

// dodataState holds bits of state information needed by dodata() and the
// various helpers it calls. The lifetime of these items should not extend
// past the end of dodata().
type dodataState struct {
	// Link context
	ctxt *Link
	// Data symbols bucketed by type.
	data [sym.SXREF][]loader.Sym
	// Max alignment for each flavor of data symbol.
	dataMaxAlign [sym.SXREF]int32
	// Overridden sym type
	symGroupType []sym.SymKind
	// Current data size so far.
	datsize int64
}

// A note on symType/setSymType below:
//
// In the legacy linker, the types of symbols (notably data symbols) are
// changed during the symtab() phase so as to insure that similar symbols
// are bucketed together, then their types are changed back again during
// dodata. Symbol to section assignment also plays tricks along these lines
// in the case where a relro segment is needed.
//
// The value returned from setType() below reflects the effects of
// any overrides made by symtab and/or dodata.

// symType returns the (possibly overridden) type of 's'.
func (state *dodataState) symType(s loader.Sym) sym.SymKind {
	if int(s) < len(state.symGroupType) {
		if override := state.symGroupType[s]; override != 0 {
			return override
		}
	}
	return state.ctxt.loader.SymType(s)
}

// setSymType sets a new override type for 's'.
func (state *dodataState) setSymType(s loader.Sym, kind sym.SymKind) {
	if s == 0 {
		panic("bad")
	}
	if int(s) < len(state.symGroupType) {
		state.symGroupType[s] = kind
	} else {
		su := state.ctxt.loader.MakeSymbolUpdater(s)
		su.SetType(kind)
	}
}

func (ctxt *Link) dodata(symGroupType []sym.SymKind) {

	// Give zeros sized symbols space if necessary.
	fixZeroSizedSymbols(ctxt)

	// Collect data symbols by type into data.
	state := dodataState{ctxt: ctxt, symGroupType: symGroupType}
	ldr := ctxt.loader
	for s := loader.Sym(1); s < loader.Sym(ldr.NSym()); s++ {
		if !ldr.AttrReachable(s) || ldr.AttrSpecial(s) || ldr.AttrSubSymbol(s) ||
			!ldr.TopLevelSym(s) {
			continue
		}

		st := state.symType(s)

		if st <= sym.STEXTFIPSEND || st >= sym.SXREF {
			continue
		}
		state.data[st] = append(state.data[st], s)

		// Similarly with checking the onlist attr.
		if ldr.AttrOnList(s) {
			log.Fatalf("symbol %s listed multiple times", ldr.SymName(s))
		}
		ldr.SetAttrOnList(s, true)
	}

	// Now that we have the data symbols, but before we start
	// to assign addresses, record all the necessary
	// dynamic relocations. These will grow the relocation
	// symbol, which is itself data.
	//
	// On darwin, we need the symbol table numbers for dynreloc.
	if ctxt.HeadType == objabi.Hdarwin {
		machosymorder(ctxt)
	}
	state.dynreloc(ctxt)

	// Move any RO data with relocations to a separate section.
	state.makeRelroForSharedLib(ctxt)

	// Set alignment for the symbol with the largest known index,
	// so as to trigger allocation of the loader's internal
	// alignment array. This will avoid data races in the parallel
	// section below.
	lastSym := loader.Sym(ldr.NSym() - 1)
	ldr.SetSymAlign(lastSym, ldr.SymAlign(lastSym))

	// Sort symbols.
	var wg sync.WaitGroup
	for symn := range state.data {
		symn := sym.SymKind(symn)
		wg.Add(1)
		go func() {
			state.data[symn], state.dataMaxAlign[symn] = state.dodataSect(ctxt, symn, state.data[symn])
			wg.Done()
		}()
	}
	wg.Wait()

	if ctxt.IsELF {
		// Make .rela and .rela.plt contiguous, the ELF ABI requires this
		// and Solaris actually cares.
		syms := state.data[sym.SELFROSECT]
		reli, plti := -1, -1
		for i, s := range syms {
			switch ldr.SymName(s) {
			case ".rel.plt", ".rela.plt":
				plti = i
			case ".rel", ".rela":
				reli = i
			}
		}
		if reli >= 0 && plti >= 0 && plti != reli+1 {
			var first, second int
			if plti > reli {
				first, second = reli, plti
			} else {
				first, second = plti, reli
			}
			rel, plt := syms[reli], syms[plti]
			copy(syms[first+2:], syms[first+1:second])
			syms[first+0] = rel
			syms[first+1] = plt

			// Make sure alignment doesn't introduce a gap.
			// Setting the alignment explicitly prevents
			// symalign from basing it on the size and
			// getting it wrong.
			ldr.SetSymAlign(rel, int32(ctxt.Arch.RegSize))
			ldr.SetSymAlign(plt, int32(ctxt.Arch.RegSize))
		}
		state.data[sym.SELFROSECT] = syms
	}

	if ctxt.HeadType == objabi.Haix && ctxt.LinkMode == LinkExternal {
		// These symbols must have the same alignment as their section.
		// Otherwise, ld might change the layout of Go sections.
		ldr.SetSymAlign(ldr.Lookup("runtime.data", 0), state.dataMaxAlign[sym.SDATA])
		ldr.SetSymAlign(ldr.Lookup("runtime.bss", 0), state.dataMaxAlign[sym.SBSS])
	}

	// Create *sym.Section objects and assign symbols to sections for
	// data/rodata (and related) symbols.
	state.allocateDataSections(ctxt)

	state.allocateSEHSections(ctxt)

	// Create *sym.Section objects and assign symbols to sections for
	// DWARF symbols.
	state.allocateDwarfSections(ctxt)

	/* number the sections */
	n := int16(1)

	for _, sect := range Segtext.Sections {
		sect.Extnum = n
		n++
	}
	for _, sect := range Segrodata.Sections {
		sect.Extnum = n
		n++
	}
	for _, sect := range Segrelrodata.Sections {
		sect.Extnum = n
		n++
	}
	for _, sect := range Segdata.Sections {
		sect.Extnum = n
		n++
	}
	for _, sect := range Segdwarf.Sections {
		sect.Extnum = n
		n++
	}
	for _, sect := range Segpdata.Sections {
		sect.Extnum = n
		n++
	}
	for _, sect := range Segxdata.Sections {
		sect.Extnum = n
		n++
	}
}

// allocateDataSectionForSym creates a new sym.Section into which a
// single symbol will be placed. Here "seg" is the segment into which
// the section will go, "s" is the symbol to be placed into the new
// section, and "rwx" contains permissions for the section.
func (state *dodataState) allocateDataSectionForSym(seg *sym.Segment, s loader.Sym, rwx int) *sym.Section {
	ldr := state.ctxt.loader
	sname := ldr.SymName(s)
	if strings.HasPrefix(sname, "go:") {
		sname = ".go." + sname[len("go:"):]
	}
	sect := addsection(ldr, state.ctxt.Arch, seg, sname, rwx)
	sect.Align = symalign(ldr, s)
	state.datsize = Rnd(state.datsize, int64(sect.Align))
	sect.Vaddr = uint64(state.datsize)
	return sect
}

// allocateNamedDataSection creates a new sym.Section for a category
// of data symbols. Here "seg" is the segment into which the section
// will go, "sName" is the name to give to the section, "types" is a
// range of symbol types to be put into the section, and "rwx"
// contains permissions for the section.
func (state *dodataState) allocateNamedDataSection(seg *sym.Segment, sName string, types []sym.SymKind, rwx int) *sym.Section {
	sect := addsection(state.ctxt.loader, state.ctxt.Arch, seg, sName, rwx)
	if len(types) == 0 {
		sect.Align = 1
	} else if len(types) == 1 {
		sect.Align = state.dataMaxAlign[types[0]]
	} else {
		for _, symn := range types {
			align := state.dataMaxAlign[symn]
			if sect.Align < align {
				sect.Align = align
			}
		}
	}
	state.datsize = Rnd(state.datsize, int64(sect.Align))
	sect.Vaddr = uint64(state.datsize)
	return sect
}

// assignDsymsToSection assigns a collection of data symbols to a
// newly created section. "sect" is the section into which to place
// the symbols, "syms" holds the list of symbols to assign,
// "forceType" (if non-zero) contains a new sym type to apply to each
// sym during the assignment, and "aligner" is a hook to call to
// handle alignment during the assignment process.
func (state *dodataState) assignDsymsToSection(sect *sym.Section, syms []loader.Sym, forceType sym.SymKind, aligner func(state *dodataState, datsize int64, s loader.Sym) int64) {
	ldr := state.ctxt.loader
	for _, s := range syms {
		state.datsize = aligner(state, state.datsize, s)
		ldr.SetSymSect(s, sect)
		if forceType != sym.Sxxx {
			state.setSymType(s, forceType)
		}
		ldr.SetSymValue(s, int64(uint64(state.datsize)-sect.Vaddr))
		state.datsize += ldr.SymSize(s)
	}
	sect.Length = uint64(state.datsize) - sect.Vaddr
}

func (state *dodataState) assignToSection(sect *sym.Section, symn sym.SymKind, forceType sym.SymKind) {
	state.assignDsymsToSection(sect, state.data[symn], forceType, aligndatsize)
	state.checkdatsize(symn)
}

// allocateSingleSymSections walks through the bucketed data symbols
// with type 'symn', creates a new section for each sym, and assigns
// the sym to a newly created section. Section name is set from the
// symbol name. "Seg" is the segment into which to place the new
// section, "forceType" is the new sym.SymKind to assign to the symbol
// within the section, and "rwx" holds section permissions.
func (state *dodataState) allocateSingleSymSections(seg *sym.Segment, symn sym.SymKind, forceType sym.SymKind, rwx int) {
	ldr := state.ctxt.loader
	for _, s := range state.data[symn] {
		sect := state.allocateDataSectionForSym(seg, s, rwx)
		ldr.SetSymSect(s, sect)
		state.setSymType(s, forceType)
		ldr.SetSymValue(s, int64(uint64(state.datsize)-sect.Vaddr))
		state.datsize += ldr.SymSize(s)
		sect.Length = uint64(state.datsize) - sect.Vaddr
	}
	state.checkdatsize(symn)
}

// allocateNamedSectionAndAssignSyms creates a new section with the
// specified name, then walks through the bucketed data symbols with
// type 'symn' and assigns each of them to this new section. "Seg" is
// the segment into which to place the new section, "secName" is the
// name to give to the new section, "forceType" (if non-zero) contains
// a new sym type to apply to each sym during the assignment, and
// "rwx" holds section permissions.
func (state *dodataState) allocateNamedSectionAndAssignSyms(seg *sym.Segment, secName string, symn sym.SymKind, forceType sym.SymKind, rwx int) *sym.Section {

	sect := state.allocateNamedDataSection(seg, secName, []sym.SymKind{symn}, rwx)
	state.assignDsymsToSection(sect, state.data[symn], forceType, aligndatsize)
	return sect
}

// allocateDataSections allocates sym.Section objects for data/rodata
// (and related) symbols, and then assigns symbols to those sections.
func (state *dodataState) allocateDataSections(ctxt *Link) {
	// Allocate sections.
	// Data is processed before segtext, because we need
	// to see all symbols in the .data and .bss sections in order
	// to generate garbage collection information.

	// Writable data sections that do not need any specialized handling.
	writable := []sym.SymKind{
		sym.SBUILDINFO,
		sym.SFIPSINFO,
		sym.SELFSECT,
		sym.SMACHO,
		sym.SMACHOGOT,
		sym.SWINDOWS,
	}
	for _, symn := range writable {
		state.allocateSingleSymSections(&Segdata, symn, sym.SDATA, 06)
	}
	ldr := ctxt.loader

	// writable .got (note that for PIE binaries .got goes in relro)
	if len(state.data[sym.SELFGOT]) > 0 {
		state.allocateNamedSectionAndAssignSyms(&Segdata, ".got", sym.SELFGOT, sym.SDATA, 06)
	}

	/* pointer-free data */
	sect := state.allocateNamedSectionAndAssignSyms(&Segdata, ".noptrdata", sym.SNOPTRDATA, sym.SDATA, 06)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.noptrdata", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.enoptrdata", 0), sect)

	state.assignToSection(sect, sym.SNOPTRDATAFIPSSTART, sym.SDATA)
	state.assignToSection(sect, sym.SNOPTRDATAFIPS, sym.SDATA)
	state.assignToSection(sect, sym.SNOPTRDATAFIPSEND, sym.SDATA)
	state.assignToSection(sect, sym.SNOPTRDATAEND, sym.SDATA)

	hasinitarr := ctxt.linkShared

	/* shared library initializer */
	switch ctxt.BuildMode {
	case BuildModeCArchive, BuildModeCShared, BuildModeShared, BuildModePlugin:
		hasinitarr = true
	}

	if ctxt.HeadType == objabi.Haix {
		if len(state.data[sym.SINITARR]) > 0 {
			Errorf("XCOFF format doesn't allow .init_array section")
		}
	}

	if hasinitarr && len(state.data[sym.SINITARR]) > 0 {
		state.allocateNamedSectionAndAssignSyms(&Segdata, ".init_array", sym.SINITARR, sym.Sxxx, 06)
	}

	/* data */
	sect = state.allocateNamedSectionAndAssignSyms(&Segdata, ".data", sym.SDATA, sym.SDATA, 06)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.data", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.edata", 0), sect)

	state.assignToSection(sect, sym.SDATAFIPSSTART, sym.SDATA)
	state.assignToSection(sect, sym.SDATAFIPS, sym.SDATA)
	state.assignToSection(sect, sym.SDATAFIPSEND, sym.SDATA)
	state.assignToSection(sect, sym.SDATAEND, sym.SDATA)

	dataGcEnd := state.datsize - int64(sect.Vaddr)

	// On AIX, TOC entries must be the last of .data
	// These aren't part of gc as they won't change during the runtime.
	state.assignToSection(sect, sym.SXCOFFTOC, sym.SDATA)
	state.checkdatsize(sym.SDATA)
	sect.Length = uint64(state.datsize) - sect.Vaddr

	/* bss */
	sect = state.allocateNamedSectionAndAssignSyms(&Segdata, ".bss", sym.SBSS, sym.Sxxx, 06)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.bss", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.ebss", 0), sect)
	bssGcEnd := state.datsize - int64(sect.Vaddr)

	// Emit gcdata for bss symbols now that symbol values have been assigned.
	gcsToEmit := []struct {
		symName string
		symKind sym.SymKind
		gcEnd   int64
	}{
		{"runtime.gcdata", sym.SDATA, dataGcEnd},
		{"runtime.gcbss", sym.SBSS, bssGcEnd},
	}
	for _, g := range gcsToEmit {
		var gc GCProg
		gc.Init(ctxt, g.symName)
		for _, s := range state.data[g.symKind] {
			gc.AddSym(s)
		}
		gc.End(g.gcEnd)
	}

	/* pointer-free bss */
	sect = state.allocateNamedSectionAndAssignSyms(&Segdata, ".noptrbss", sym.SNOPTRBSS, sym.Sxxx, 06)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.noptrbss", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.enoptrbss", 0), sect)

	// Code coverage counters are assigned to the .noptrbss section.
	// We assign them in a separate pass so that they stay aggregated
	// together in a single blob (coverage runtime depends on this).
	covCounterDataStartOff = sect.Length
	state.assignToSection(sect, sym.SCOVERAGE_COUNTER, sym.SNOPTRBSS)
	covCounterDataLen = sect.Length - covCounterDataStartOff
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.covctrs", 0), sect)
	ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.ecovctrs", 0), sect)

	// Coverage instrumentation counters for libfuzzer.
	if len(state.data[sym.SLIBFUZZER_8BIT_COUNTER]) > 0 {
		sect := state.allocateNamedSectionAndAssignSyms(&Segdata, ".go.fuzzcntrs", sym.SLIBFUZZER_8BIT_COUNTER, sym.Sxxx, 06)
		ldr.SetSymSect(ldr.LookupOrCreateSym("runtime.__start___sancov_cntrs", 0), sect)
		ldr.SetSymSect(ldr.LookupOrCreateSym("runti
"""




```