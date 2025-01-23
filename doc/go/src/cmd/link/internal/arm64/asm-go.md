Response:
The user wants a breakdown of the `asm.go` file for the ARM64 architecture in the Go linker. I need to identify the functionalities implemented in this file and provide examples where applicable.

Here's a plan:
1. **Identify the main functions**: Look for top-level function declarations like `gentext`, `adddynrel`, `elfreloc1`, etc.
2. **Describe the purpose of each function**:  Infer the function's role based on its name, the types it operates on, and the operations it performs. Pay attention to interactions with linker data structures like `ld.Link`, `loader.Loader`, `loader.SymbolBuilder`, etc.
3. **Relate functions to Go language features**:  If a function seems related to a specific Go feature (like dynamic linking, TLS, or function calls), try to provide a Go code example that would trigger its execution. This might require some educated guesses and simplifying assumptions.
4. **Explain code reasoning**: For functions involving more complex logic (like relocation handling), describe the assumed input, the steps taken by the code, and the expected output.
5. **Detail command-line parameter handling**: Examine if any functions directly process command-line arguments. This seems less likely in this specific file, which is more about the linking logic.
6. **Identify common mistakes**: Based on the function's purpose and the potential for errors (e.g., incorrect relocation types, out-of-range offsets), point out common mistakes users might make.`go/src/cmd/link/internal/arm64/asm.go` 是 Go 语言链接器 `cmd/link` 中专门处理 ARM64 架构汇编相关的代码。它的主要功能包括：

**1. 生成启动代码 (`gentext`)**

   -  此函数负责生成一小段启动代码，用于在程序启动时初始化 `runtime` 包的 `firstmoduledata` 变量。
   -  它将 `local.moduledata` 的地址加载到寄存器 `x0`，然后调用 `runtime.addmoduledata` 函数来注册模块数据。

   ```go
   func gentext(ctxt *ld.Link, ldr *loader.Loader) {
       initfunc, addmoduledata := ld.PrepareAddmoduledata(ctxt)
       if initfunc == nil {
           return
       }

       o := func(op uint32) {
           initfunc.AddUint32(ctxt.Arch, op)
       }

       // Load address of local.moduledata into x0
       o(0x90000000) // adrp	x0, 0 <runtime.firstmoduledata>
       o(0x91000000) // add	x0, x0, #0x0
       rel, _ := initfunc.AddRel(objabi.R_ADDRARM64)
       rel.SetOff(0)
       rel.SetSiz(8)
       rel.SetSym(ctxt.Moduledata)

       // Call runtime.addmoduledata
       o(0x14000000) // b	0 <runtime.addmoduledata>
       rel2, _ := initfunc.AddRel(objabi.R_CALLARM64)
       rel2.SetOff(8)
       rel2.SetSiz(4)
       rel2.SetSym(addmoduledata)
   }
   ```

   **推断的 Go 语言功能实现:**  这部分代码是 Go 程序启动过程中的一部分，与 `runtime` 包的初始化密切相关。 `runtime.firstmoduledata` 存储了程序加载的第一个模块的元数据。

   **Go 代码示例:**  虽然不能直接触发 `gentext` 函数，但理解其作用有助于理解 Go 程序的启动流程。在任何 Go 程序启动时，都会执行类似的初始化过程。

   ```go
   package main

   import "fmt"

   func main() {
       fmt.Println("Hello, world!")
   }
   ```

   **假设的输入与输出:**  `gentext` 函数的输入是链接上下文 `ctxt` 和加载器 `ldr`。 输出是在 `initfunc` 符号中添加了一系列 ARM64 指令。

**2. 添加动态重定位信息 (`adddynrel`)**

   - 此函数处理将目标文件中的重定位信息转换为链接器内部的表示，并根据需要添加动态链接所需的重定位。
   - 它根据重定位类型 (`r.Type()`) 和目标符号的类型 (`targType`) 进行不同的处理，例如：
     - 处理 PC 相对的重定位 (`R_AARCH64_PREL32`, `R_AARCH64_PREL64`)。
     - 处理函数调用重定位 (`R_AARCH64_CALL26`, `R_AARCH64_JUMP26`)，如果目标是动态导入的符号，则会调用 `addpltsym` 来创建 PLT 条目。
     - 处理访问 GOT (Global Offset Table) 的重定位 (`R_AARCH64_ADR_GOT_PAGE`, `R_AARCH64_LD64_GOT_LO12_NC`)。
     - 处理绝对地址重定位 (`R_AARCH64_ABS64`)。
     - 处理加载/存储指令的重定位 (`R_AARCH64_LDST*_ABS_LO12_NC`)。
     - 处理 Mach-O 文件格式的重定位。

   **推断的 Go 语言功能实现:**  这部分代码是实现 Go 语言动态链接的关键部分，用于支持 `import` 外部包或者使用 `//go:cgo_export` 导出符号。

   **Go 代码示例:**  以下代码展示了一个使用动态链接的场景 (需要 C 代码和 cgo)：

   ```go
   package main

   //#include <stdio.h>
   //void helloFromC() {
   //    printf("Hello from C!\n");
   //}
   import "C"

   import "fmt"

   func main() {
       fmt.Println("Hello from Go!")
       C.helloFromC()
   }
   ```

   **假设的输入与输出:**  `adddynrel` 的输入包括目标平台信息 `target`，加载器 `ldr`，架构相关的符号信息 `syms`，当前符号 `s`，重定位信息 `r` 及其索引 `rIdx`。 输出是函数返回一个布尔值，指示是否成功处理了重定位，并可能修改了 `ldr` 中存储的重定位信息。 例如，对于 `R_AARCH64_CALL26` 类型的重定位，如果目标是动态符号，则会添加 PLT 条目，并将重定位目标修改为 PLT 表的符号。

   **命令行参数的具体处理:**  此函数本身不直接处理命令行参数。但是，链接器的其他部分会根据命令行参数（如 `-buildmode=c-shared` 或 `-linkshared`）的设置来决定是否需要进行动态链接，从而影响 `adddynrel` 的执行。

**3. 生成 ELF 格式的重定位条目 (`elfreloc1`)**

   - 此函数将链接器内部的重定位信息转换为 ELF (Executable and Linkable Format) 格式的重定位条目，以便在生成 ELF 可执行文件或共享库时使用。
   - 它根据重定位类型 (`r.Type`) 生成不同的 ELF 重定位条目，例如 `R_AARCH64_ABS32`, `R_AARCH64_ABS64`, `R_AARCH64_CALL26` 等。

   **推断的 Go 语言功能实现:**  当使用 `-buildmode=exe` 或 `-buildmode=c-shared` 并且目标平台是 Linux 等使用 ELF 格式的操作系统时，会用到此函数。

   **Go 代码示例:**  生成 ELF 可执行文件：

   ```bash
   go build -o myapp main.go
   ```

   **假设的输入与输出:**  `elfreloc1` 的输入包括链接上下文 `ctxt`，输出缓冲区 `out`，加载器 `ldr`，当前符号 `s`，外部重定位信息 `r`，重定位的索引 `ri` 和所在 section 的偏移量 `sectoff`。 输出是将生成的 ELF 重定位条目写入到 `out` 缓冲区。 例如，对于 `objabi.R_ADDRARM64` 类型的重定位，会生成两个 ELF 重定位条目 `R_AARCH64_ADR_PREL_PG_HI21` 和 `R_AARCH64_ADD_ABS_LO12_NC`。

**4. 生成 Mach-O 格式的重定位条目 (`machoreloc1`)**

   - 此函数类似于 `elfreloc1`，但用于将重定位信息转换为 macOS 和 iOS 等系统使用的 Mach-O 格式。
   - 它处理 Mach-O 特定的重定位类型，并根据需要生成多个重定位条目。

   **推断的 Go 语言功能实现:**  当使用 `-buildmode=exe` 或 `-buildmode=c-shared` 并且目标平台是 Darwin (macOS/iOS) 时，会用到此函数。

   **Go 代码示例:**  生成 Mach-O 可执行文件：

   ```bash
   GOOS=darwin GOARCH=arm64 go build -o myapp main.go
   ```

   **假设的输入与输出:**  `machoreloc1` 的输入包括架构信息 `arch`，输出缓冲区 `out`，加载器 `ldr`，当前符号 `s`，外部重定位信息 `r` 和所在 section 的偏移量 `sectoff`。 输出是将生成的 Mach-O 重定位条目写入到 `out` 缓冲区。

**5. 生成 PE 格式的重定位条目 (`pereloc1`)**

   - 此函数类似于 `elfreloc1` 和 `machoreloc1`，但用于将重定位信息转换为 Windows 系统使用的 PE (Portable Executable) 格式。
   - 它处理 PE 特定的重定位类型。

   **推断的 Go 语言功能实现:**  当使用 `-buildmode=exe` 并且目标平台是 Windows 时，会用到此函数。

   **Go 代码示例:**  生成 PE 可执行文件：

   ```bash
   GOOS=windows GOARCH=arm64 go build -o myapp.exe main.go
   ```

   **假设的输入与输出:**  `pereloc1` 的输入包括架构信息 `arch`，输出缓冲区 `out`，加载器 `ldr`，当前符号 `s`，外部重定位信息 `r` 和所在 section 的偏移量 `sectoff`。 输出是将生成的 PE 重定位条目写入到 `out` 缓冲区。

**6. 执行架构相关的重定位 (`archreloc`)**

   - 此函数负责执行特定于 ARM64 架构的重定位操作，例如计算 PC 相对偏移、处理 TLS (Thread-Local Storage) 相关的重定位等。
   - 它根据重定位类型修改指令中的相应字段。

   **推断的 Go 语言功能实现:**  所有涉及 ARM64 指令的重定位都会经过此函数处理，包括函数调用、数据访问等。

   **Go 代码示例:**  任何 Go 程序在编译到 ARM64 架构时都会执行此函数中的代码。

   **假设的输入与输出:**  `archreloc` 的输入包括目标平台信息 `target`，加载器 `ldr`，架构相关的符号信息 `syms`，重定位信息 `r`，当前符号 `s` 和重定位处的值 `val`。 输出是修改后的 `val`，表示应用重定位后的指令值，以及是否需要额外的外部重定位信息。 例如，对于 `objabi.R_ADDRARM64` 类型的重定位，会根据目标地址计算出 ADRP 和 ADD 指令所需的立即数，并更新 `val` 的相应位。

**7. 处理外部重定位 (`extreloc`)**

   - 此函数确定是否需要为给定的重定位创建外部重定位条目，以便在最终链接时由外部链接器处理。

   **推断的 Go 语言功能实现:**  当使用外部链接器时（通常在 CGO 的场景下），此函数用于生成传递给外部链接器的重定位信息。

   **Go 代码示例:**  涉及到 CGO 的代码会触发此函数。

   **假设的输入与输出:**  `extreloc` 的输入包括目标平台信息 `target`，加载器 `ldr`，重定位信息 `r` 和当前符号 `s`。 输出是一个 `loader.ExtReloc` 结构体，包含了需要传递给外部链接器的重定位信息，以及一个布尔值指示是否需要外部重定位。

**8. 设置 PLT (Procedure Linkage Table) (`elfsetupplt`)**

   - 此函数负责在生成 ELF 格式的可执行文件或共享库时，设置 PLT 表的初始内容。 PLT 用于延迟解析动态链接的函数调用。

   **推断的 Go 语言功能实现:**  当进行动态链接并且目标平台是 Linux 等使用 ELF 格式的操作系统时，会用到此函数。

   **Go 代码示例:**  使用动态链接的 Go 程序。

   **假设的输入与输出:**  `elfsetupplt` 的输入包括链接上下文 `ctxt`，加载器 `ldr`，PLT 表的符号构建器 `plt`，GOT.PLT 表的符号构建器 `gotplt` 和动态符号表 `dynamic`。 输出是在 `plt` 和 `gotplt` 符号中添加了用于 PLT 初始化的 ARM64 指令。

**9. 添加 PLT 符号 (`addpltsym`)**

   - 此函数用于向 PLT 表中添加一个条目，以便动态链接器能够解析对外部符号的调用。

   **推断的 Go 语言功能实现:**  当调用动态链接的外部函数时，会调用此函数来创建 PLT 条目。

   **Go 代码示例:**  调用 CGO 导出的函数或链接到共享库中的函数。

   **假设的输入与输出:**  `addpltsym` 的输入包括目标平台信息 `target`，加载器 `ldr`，架构相关的符号信息 `syms` 和需要添加到 PLT 的符号 `s`。 输出是在 PLT 表 (`syms.PLT`) 和 GOT.PLT 表 (`syms.GOTPLT`) 中添加相应的条目，并将符号 `s` 的 PLT 索引记录下来。

**10. 生成符号别名 (`gensymlate`)**

    - 为了解决外部链接器在处理大偏移量时的限制（例如 Mach-O 的 24 位有符号偏移和 PE 的 21 位有符号偏移），此函数会生成额外的 "label" 符号。
    - 当目标符号的偏移量过大时，重定位可以指向这些中间的 "label" 符号，从而减小偏移量。

    **推断的 Go 语言功能实现:**  在外部链接的场景下，当目标文件非常大，或者涉及到对大符号的重定位时，会使用此功能。

    **Go 代码示例:**  通常在构建大型的、需要外部链接的 Go 程序时可能会触发。

    **假设的输入与输出:**  `gensymlate` 的输入是链接上下文 `ctxt` 和加载器 `ldr`。 输出是在符号表中创建了额外的 "label" 符号，这些符号指向原符号的特定偏移量。

**11. 获取偏移标签名称 (`offsetLabelName`)**

    -  为 `gensymlate` 生成的 "label" 符号生成名称。

**12. 生成跳转指令的跳转桩 (`trampoline`)**

    - 当直接跳转的目标地址超出指令的寻址范围时，此函数会生成一个跳转桩 (trampoline)。
    - 跳转指令会先跳转到这个跳转桩，然后跳转桩再无条件跳转到目标地址。

    **推断的 Go 语言功能实现:**  当跨包调用函数，或者调用距离较远的函数时，可能会需要生成跳转桩。

    **Go 代码示例:**  在大型项目中，或者涉及跨多个包的频繁调用时。

    **假设的输入与输出:**  `trampoline` 的输入包括链接上下文 `ctxt`，加载器 `ldr`，重定位的索引 `ri`，目标符号 `rs` 和当前符号 `s`。 输出是如果需要跳转桩，则会在符号表中创建一个新的跳转桩符号，并修改原始的重定位信息，使其指向跳转桩。

**13. 生成跳转桩的代码 (`gentramp`, `gentrampgot`)**

    - `gentramp` 生成普通的跳转桩代码。
    - `gentrampgot` 生成通过 GOT 表进行跳转的跳转桩代码，用于动态链接的符号。

**使用者易犯错的点 (基于代码推理):**

1. **不理解重定位类型:**  错误地假设或使用错误的重定位类型可能导致链接错误或运行时错误。例如，将本应该使用 PC 相对重定位的指令使用了绝对地址重定位。
2. **外部链接时的偏移量限制:** 在使用外部链接器 (如 CGO) 时，如果目标符号的偏移量过大，可能会导致链接失败。需要理解 `gensymlate` 的作用，并避免超出外部链接器支持的偏移量范围。
3. **跳转范围限制:**  直接函数调用指令有一定的跳转范围限制。如果跨模块调用函数且距离过远，可能会导致链接错误。 需要理解跳转桩 (`trampoline`) 的作用。
4. **动态链接符号的处理:**  不理解 PLT 和 GOT 的工作原理，可能在手动操作链接过程或编写汇编代码时出错。例如，不正确地设置 GOT 表项或者 PLT 跳转目标。

**示例说明易犯错的点:**

假设在一个 CGO 项目中，Go 代码需要调用一个 C 函数，但该 C 函数的地址与 Go 代码的调用点距离很远，超出了直接跳转指令的范围。

```go
package main

/*
#include <stdio.h>

void very_far_function() {
    // ... 很多代码 ...
    printf("Hello from C!\n");
}
*/
import "C"

func main() {
    C.very_far_function() // 如果 very_far_function 距离 main 函数很远，可能需要 trampoline
}
```

在这种情况下，如果链接器没有正确地生成跳转桩，可能会导致链接错误或者运行时程序崩溃。链接器会分析调用距离，如果超出范围，则会生成一个 `trampoline` 函数，`main` 函数先调用 `trampoline`，然后 `trampoline` 再跳转到 `very_far_function`。

总结来说，`go/src/cmd/link/internal/arm64/asm.go` 文件是 Go 语言链接器中处理 ARM64 架构汇编指令和重定位的核心部分，它负责生成启动代码、处理各种类型的重定位、生成不同目标文件格式的重定位信息，以及处理动态链接和长跳转等复杂场景。理解其功能对于深入了解 Go 语言的链接过程至关重要。

### 提示词
```
这是路径为go/src/cmd/link/internal/arm64/asm.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package arm64

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

func gentext(ctxt *ld.Link, ldr *loader.Loader) {
	initfunc, addmoduledata := ld.PrepareAddmoduledata(ctxt)
	if initfunc == nil {
		return
	}

	o := func(op uint32) {
		initfunc.AddUint32(ctxt.Arch, op)
	}
	// 0000000000000000 <local.dso_init>:
	// 0:	90000000 	adrp	x0, 0 <runtime.firstmoduledata>
	// 	0: R_AARCH64_ADR_PREL_PG_HI21	local.moduledata
	// 4:	91000000 	add	x0, x0, #0x0
	// 	4: R_AARCH64_ADD_ABS_LO12_NC	local.moduledata
	o(0x90000000)
	o(0x91000000)
	rel, _ := initfunc.AddRel(objabi.R_ADDRARM64)
	rel.SetOff(0)
	rel.SetSiz(8)
	rel.SetSym(ctxt.Moduledata)

	// 8:	14000000 	b	0 <runtime.addmoduledata>
	// 	8: R_AARCH64_CALL26	runtime.addmoduledata
	o(0x14000000)
	rel2, _ := initfunc.AddRel(objabi.R_CALLARM64)
	rel2.SetOff(8)
	rel2.SetSiz(4)
	rel2.SetSym(addmoduledata)
}

func adddynrel(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, s loader.Sym, r loader.Reloc, rIdx int) bool {
	targ := r.Sym()
	var targType sym.SymKind
	if targ != 0 {
		targType = ldr.SymType(targ)
	}

	const pcrel = 1
	switch r.Type() {
	default:
		if r.Type() >= objabi.ElfRelocOffset {
			ldr.Errorf(s, "unexpected relocation type %d (%s)", r.Type(), sym.RelocName(target.Arch, r.Type()))
			return false
		}

	// Handle relocations found in ELF object files.
	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_PREL32):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_AARCH64_PREL32 relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		if targType == 0 || targType == sym.SXREF {
			ldr.Errorf(s, "unknown symbol %s in pcrel", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocAdd(rIdx, r.Add()+4)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_PREL64):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_AARCH64_PREL64 relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		if targType == 0 || targType == sym.SXREF {
			ldr.Errorf(s, "unknown symbol %s in pcrel", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_PCREL)
		su.SetRelocAdd(rIdx, r.Add()+8)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_CALL26),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_JUMP26):
		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			su := ldr.MakeSymbolUpdater(s)
			su.SetRelocSym(rIdx, syms.PLT)
			su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymPlt(targ)))
		}
		if targType == 0 || targType == sym.SXREF {
			ldr.Errorf(s, "unknown symbol %s in callarm64", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_CALLARM64)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_ADR_GOT_PAGE),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_LD64_GOT_LO12_NC):
		if targType != sym.SDYNIMPORT {
			// have symbol
			// TODO: turn LDR of GOT entry into ADR of symbol itself
		}

		// fall back to using GOT
		// TODO: just needs relocation, no need to put in .dynsym
		ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_AARCH64_GLOB_DAT))
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ARM64_GOT)
		su.SetRelocSym(rIdx, syms.GOT)
		su.SetRelocAdd(rIdx, r.Add()+int64(ldr.SymGot(targ)))
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_ADR_PREL_PG_HI21),
		objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_ADD_ABS_LO12_NC):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		if targType == 0 || targType == sym.SXREF {
			ldr.Errorf(s, "unknown symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ARM64_PCREL)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_ABS64):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected R_AARCH64_ABS64 relocation for dynamic symbol %s", ldr.SymName(targ))
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

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_LDST8_ABS_LO12_NC):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ARM64_LDST8)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_LDST16_ABS_LO12_NC):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ARM64_LDST16)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_LDST32_ABS_LO12_NC):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ARM64_LDST32)
		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_LDST64_ABS_LO12_NC):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ARM64_LDST64)

		return true

	case objabi.ElfRelocOffset + objabi.RelocType(elf.R_AARCH64_LDST128_ABS_LO12_NC):
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ARM64_LDST128)
		return true

	// Handle relocations found in Mach-O object files.
	case objabi.MachoRelocOffset + ld.MACHO_ARM64_RELOC_UNSIGNED*2:
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected reloc for dynamic symbol %s", ldr.SymName(targ))
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

	case objabi.MachoRelocOffset + ld.MACHO_ARM64_RELOC_BRANCH26*2 + pcrel:
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_CALLARM64)
		if targType == sym.SDYNIMPORT {
			addpltsym(target, ldr, syms, targ)
			su.SetRelocSym(rIdx, syms.PLT)
			su.SetRelocAdd(rIdx, int64(ldr.SymPlt(targ)))
		}
		return true

	case objabi.MachoRelocOffset + ld.MACHO_ARM64_RELOC_PAGE21*2 + pcrel,
		objabi.MachoRelocOffset + ld.MACHO_ARM64_RELOC_PAGEOFF12*2:
		if targType == sym.SDYNIMPORT {
			ldr.Errorf(s, "unexpected relocation for dynamic symbol %s", ldr.SymName(targ))
		}
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ARM64_PCREL)
		return true

	case objabi.MachoRelocOffset + ld.MACHO_ARM64_RELOC_GOT_LOAD_PAGE21*2 + pcrel,
		objabi.MachoRelocOffset + ld.MACHO_ARM64_RELOC_GOT_LOAD_PAGEOFF12*2:
		if targType != sym.SDYNIMPORT {
			// have symbol
			// turn MOVD sym@GOT (adrp+ldr) into MOVD $sym (adrp+add)
			data := ldr.Data(s)
			off := r.Off()
			if int(off+3) >= len(data) {
				ldr.Errorf(s, "unexpected GOT_LOAD reloc for non-dynamic symbol %s", ldr.SymName(targ))
				return false
			}
			o := target.Arch.ByteOrder.Uint32(data[off:])
			su := ldr.MakeSymbolUpdater(s)
			switch {
			case (o>>24)&0x9f == 0x90: // adrp
				// keep instruction unchanged, change relocation type below
			case o>>24 == 0xf9: // ldr
				// rewrite to add
				o = (0x91 << 24) | (o & (1<<22 - 1))
				su.MakeWritable()
				su.SetUint32(target.Arch, int64(off), o)
			default:
				ldr.Errorf(s, "unexpected GOT_LOAD reloc for non-dynamic symbol %s", ldr.SymName(targ))
				return false
			}
			su.SetRelocType(rIdx, objabi.R_ARM64_PCREL)
			return true
		}
		ld.AddGotSym(target, ldr, syms, targ, 0)
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocType(rIdx, objabi.R_ARM64_GOT)
		su.SetRelocSym(rIdx, syms.GOT)
		su.SetRelocAdd(rIdx, int64(ldr.SymGot(targ)))
		return true
	}

	// Reread the reloc to incorporate any changes in type above.
	relocs := ldr.Relocs(s)
	r = relocs.At(rIdx)

	switch r.Type() {
	case objabi.R_CALLARM64:
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
			ldr.Errorf(s, "PLT call with non-zero addend (%v)", r.Add())
		}
		// Build a PLT entry and change the relocation target to that entry.
		addpltsym(target, ldr, syms, targ)
		su := ldr.MakeSymbolUpdater(s)
		su.SetRelocSym(rIdx, syms.PLT)
		su.SetRelocAdd(rIdx, int64(ldr.SymPlt(targ)))
		return true

	case objabi.R_ADDRARM64:
		if targType == sym.SDYNIMPORT && ldr.SymType(s).IsText() && target.IsDarwin() {
			// Loading the address of a dynamic symbol. Rewrite to use GOT.
			// turn MOVD $sym (adrp+add) into MOVD sym@GOT (adrp+ldr)
			if r.Add() != 0 {
				ldr.Errorf(s, "unexpected nonzero addend for dynamic symbol %s", ldr.SymName(targ))
				return false
			}
			su := ldr.MakeSymbolUpdater(s)
			data := ldr.Data(s)
			off := r.Off()
			if int(off+8) > len(data) {
				ldr.Errorf(s, "unexpected R_ADDRARM64 reloc for dynamic symbol %s", ldr.SymName(targ))
				return false
			}
			o := target.Arch.ByteOrder.Uint32(data[off+4:])
			if o>>24 == 0x91 { // add
				// rewrite to ldr
				o = (0xf9 << 24) | 1<<22 | (o & (1<<22 - 1))
				su.MakeWritable()
				su.SetUint32(target.Arch, int64(off+4), o)
				if target.IsInternal() {
					ld.AddGotSym(target, ldr, syms, targ, 0)
					su.SetRelocSym(rIdx, syms.GOT)
					su.SetRelocAdd(rIdx, int64(ldr.SymGot(targ)))
					su.SetRelocType(rIdx, objabi.R_ARM64_PCREL_LDST64)
				} else {
					su.SetRelocType(rIdx, objabi.R_ARM64_GOTPCREL)
				}
				return true
			}
			ldr.Errorf(s, "unexpected R_ADDRARM64 reloc for dynamic symbol %s", ldr.SymName(targ))
		}

	case objabi.R_ADDR:
		if ldr.SymType(s).IsText() && target.IsElf() {
			// The code is asking for the address of an external
			// function. We provide it with the address of the
			// correspondent GOT symbol.
			ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_AARCH64_GLOB_DAT))
			su := ldr.MakeSymbolUpdater(s)
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
			// Generate R_AARCH64_RELATIVE relocations for best
			// efficiency in the dynamic linker.
			//
			// As noted above, symbol addresses have not been
			// assigned yet, so we can't generate the final reloc
			// entry yet. We ultimately want:
			//
			// r_offset = s + r.Off
			// r_info = R_AARCH64_RELATIVE
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
				rela.AddUint64(target.Arch, elf.R_INFO(0, uint32(elf.R_AARCH64_RELATIVE)))
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

	case objabi.R_ARM64_GOTPCREL:
		if target.IsExternal() {
			// External linker will do this relocation.
			return true
		}
		if targType != sym.SDYNIMPORT {
			ldr.Errorf(s, "R_ARM64_GOTPCREL target is not SDYNIMPORT symbol: %v", ldr.SymName(targ))
		}
		if r.Add() != 0 {
			ldr.Errorf(s, "R_ARM64_GOTPCREL with non-zero addend (%v)", r.Add())
		}
		if target.IsElf() {
			ld.AddGotSym(target, ldr, syms, targ, uint32(elf.R_AARCH64_GLOB_DAT))
		} else {
			ld.AddGotSym(target, ldr, syms, targ, 0)
		}
		// turn into two relocations, one for each instruction.
		su := ldr.MakeSymbolUpdater(s)
		r.SetType(objabi.R_ARM64_GOT)
		r.SetSiz(4)
		r.SetSym(syms.GOT)
		r.SetAdd(int64(ldr.SymGot(targ)))
		r2, _ := su.AddRel(objabi.R_ARM64_GOT)
		r2.SetSiz(4)
		r2.SetOff(r.Off() + 4)
		r2.SetSym(syms.GOT)
		r2.SetAdd(int64(ldr.SymGot(targ)))
		return true
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
		switch siz {
		case 4:
			out.Write64(uint64(elf.R_AARCH64_ABS32) | uint64(elfsym)<<32)
		case 8:
			out.Write64(uint64(elf.R_AARCH64_ABS64) | uint64(elfsym)<<32)
		default:
			return false
		}
	case objabi.R_ADDRARM64:
		// two relocations: R_AARCH64_ADR_PREL_PG_HI21 and R_AARCH64_ADD_ABS_LO12_NC
		out.Write64(uint64(elf.R_AARCH64_ADR_PREL_PG_HI21) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_AARCH64_ADD_ABS_LO12_NC) | uint64(elfsym)<<32)

	case objabi.R_ARM64_PCREL_LDST8,
		objabi.R_ARM64_PCREL_LDST16,
		objabi.R_ARM64_PCREL_LDST32,
		objabi.R_ARM64_PCREL_LDST64:
		// two relocations: R_AARCH64_ADR_PREL_PG_HI21 and R_AARCH64_LDST{64/32/16/8}_ABS_LO12_NC
		out.Write64(uint64(elf.R_AARCH64_ADR_PREL_PG_HI21) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		var ldstType elf.R_AARCH64
		switch r.Type {
		case objabi.R_ARM64_PCREL_LDST8:
			ldstType = elf.R_AARCH64_LDST8_ABS_LO12_NC
		case objabi.R_ARM64_PCREL_LDST16:
			ldstType = elf.R_AARCH64_LDST16_ABS_LO12_NC
		case objabi.R_ARM64_PCREL_LDST32:
			ldstType = elf.R_AARCH64_LDST32_ABS_LO12_NC
		case objabi.R_ARM64_PCREL_LDST64:
			ldstType = elf.R_AARCH64_LDST64_ABS_LO12_NC
		}
		out.Write64(uint64(ldstType) | uint64(elfsym)<<32)

	case objabi.R_ARM64_TLS_LE:
		out.Write64(uint64(elf.R_AARCH64_TLSLE_MOVW_TPREL_G0) | uint64(elfsym)<<32)
	case objabi.R_ARM64_TLS_IE:
		out.Write64(uint64(elf.R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC) | uint64(elfsym)<<32)
	case objabi.R_ARM64_GOTPCREL:
		out.Write64(uint64(elf.R_AARCH64_ADR_GOT_PAGE) | uint64(elfsym)<<32)
		out.Write64(uint64(r.Xadd))
		out.Write64(uint64(sectoff + 4))
		out.Write64(uint64(elf.R_AARCH64_LD64_GOT_LO12_NC) | uint64(elfsym)<<32)
	case objabi.R_CALLARM64:
		if siz != 4 {
			return false
		}
		out.Write64(uint64(elf.R_AARCH64_CALL26) | uint64(elfsym)<<32)

	}
	out.Write64(uint64(r.Xadd))

	return true
}

// sign-extends from 21, 24-bit.
func signext21(x int64) int64 { return x << (64 - 21) >> (64 - 21) }
func signext24(x int64) int64 { return x << (64 - 24) >> (64 - 24) }

func machoreloc1(arch *sys.Arch, out *ld.OutBuf, ldr *loader.Loader, s loader.Sym, r loader.ExtReloc, sectoff int64) bool {
	var v uint32

	rs := r.Xsym
	rt := r.Type
	siz := r.Size
	xadd := r.Xadd

	if xadd != signext24(xadd) && rt != objabi.R_ADDR {
		// If the relocation target would overflow the addend, then target
		// a linker-manufactured label symbol with a smaller addend instead.
		// R_ADDR has full-width addend encoded in data content, so it doesn't
		// use a label symbol.
		label := ldr.Lookup(offsetLabelName(ldr, rs, xadd/machoRelocLimit*machoRelocLimit), ldr.SymVersion(rs))
		if label != 0 {
			xadd = ldr.SymValue(rs) + xadd - ldr.SymValue(label)
			rs = label
		}
		if xadd != signext24(xadd) {
			ldr.Errorf(s, "internal error: relocation addend overflow: %s+0x%x", ldr.SymName(rs), xadd)
		}
	}
	if rt == objabi.R_CALLARM64 && xadd != 0 {
		label := ldr.Lookup(offsetLabelName(ldr, rs, xadd), ldr.SymVersion(rs))
		if label != 0 {
			xadd = ldr.SymValue(rs) + xadd - ldr.SymValue(label) // should always be 0 (checked below)
			rs = label
		}
	}

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
		v |= ld.MACHO_ARM64_RELOC_UNSIGNED << 28
	case objabi.R_CALLARM64:
		if xadd != 0 {
			// Addend should be handled above via label symbols.
			ldr.Errorf(s, "unexpected non-zero addend: %s+%d", ldr.SymName(rs), xadd)
		}
		v |= 1 << 24 // pc-relative bit
		v |= ld.MACHO_ARM64_RELOC_BRANCH26 << 28
	case objabi.R_ADDRARM64,
		objabi.R_ARM64_PCREL_LDST8,
		objabi.R_ARM64_PCREL_LDST16,
		objabi.R_ARM64_PCREL_LDST32,
		objabi.R_ARM64_PCREL_LDST64:
		siz = 4
		// Two relocation entries: MACHO_ARM64_RELOC_PAGEOFF12 MACHO_ARM64_RELOC_PAGE21
		// if r.Xadd is non-zero, add two MACHO_ARM64_RELOC_ADDEND.
		if r.Xadd != 0 {
			out.Write32(uint32(sectoff + 4))
			out.Write32((ld.MACHO_ARM64_RELOC_ADDEND << 28) | (2 << 25) | uint32(xadd&0xffffff))
		}
		out.Write32(uint32(sectoff + 4))
		out.Write32(v | (ld.MACHO_ARM64_RELOC_PAGEOFF12 << 28) | (2 << 25))
		if r.Xadd != 0 {
			out.Write32(uint32(sectoff))
			out.Write32((ld.MACHO_ARM64_RELOC_ADDEND << 28) | (2 << 25) | uint32(xadd&0xffffff))
		}
		v |= 1 << 24 // pc-relative bit
		v |= ld.MACHO_ARM64_RELOC_PAGE21 << 28
	case objabi.R_ARM64_GOTPCREL:
		siz = 4
		// Two relocation entries: MACHO_ARM64_RELOC_GOT_LOAD_PAGEOFF12 MACHO_ARM64_RELOC_GOT_LOAD_PAGE21
		// if r.Xadd is non-zero, add two MACHO_ARM64_RELOC_ADDEND.
		if r.Xadd != 0 {
			out.Write32(uint32(sectoff + 4))
			out.Write32((ld.MACHO_ARM64_RELOC_ADDEND << 28) | (2 << 25) | uint32(xadd&0xffffff))
		}
		out.Write32(uint32(sectoff + 4))
		out.Write32(v | (ld.MACHO_ARM64_RELOC_GOT_LOAD_PAGEOFF12 << 28) | (2 << 25))
		if r.Xadd != 0 {
			out.Write32(uint32(sectoff))
			out.Write32((ld.MACHO_ARM64_RELOC_ADDEND << 28) | (2 << 25) | uint32(xadd&0xffffff))
		}
		v |= 1 << 24 // pc-relative bit
		v |= ld.MACHO_ARM64_RELOC_GOT_LOAD_PAGE21 << 28
	}

	switch siz {
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
	rs := r.Xsym
	rt := r.Type

	if (rt == objabi.R_ADDRARM64 || rt == objabi.R_ARM64_PCREL_LDST8 || rt == objabi.R_ARM64_PCREL_LDST16 ||
		rt == objabi.R_ARM64_PCREL_LDST32 || rt == objabi.R_ARM64_PCREL_LDST64) && r.Xadd != signext21(r.Xadd) {
		// If the relocation target would overflow the addend, then target
		// a linker-manufactured label symbol with a smaller addend instead.
		label := ldr.Lookup(offsetLabelName(ldr, rs, r.Xadd/peRelocLimit*peRelocLimit), ldr.SymVersion(rs))
		if label == 0 {
			ldr.Errorf(s, "invalid relocation: %v %s+0x%x", rt, ldr.SymName(rs), r.Xadd)
			return false
		}
		rs = label
	}
	if rt == objabi.R_CALLARM64 && r.Xadd != 0 {
		label := ldr.Lookup(offsetLabelName(ldr, rs, r.Xadd), ldr.SymVersion(rs))
		if label == 0 {
			ldr.Errorf(s, "invalid relocation: %v %s+0x%x", rt, ldr.SymName(rs), r.Xadd)
			return false
		}
		rs = label
	}
	symdynid := ldr.SymDynid(rs)
	if symdynid < 0 {
		ldr.Errorf(s, "reloc %d (%s) to non-coff symbol %s type=%d (%s)", rt, sym.RelocName(arch, rt), ldr.SymName(rs), ldr.SymType(rs), ldr.SymType(rs))
		return false
	}

	switch rt {
	default:
		return false

	case objabi.R_DWARFSECREF:
		out.Write32(uint32(sectoff))
		out.Write32(uint32(symdynid))
		out.Write16(ld.IMAGE_REL_ARM64_SECREL)

	case objabi.R_ADDR:
		out.Write32(uint32(sectoff))
		out.Write32(uint32(symdynid))
		if r.Size == 8 {
			out.Write16(ld.IMAGE_REL_ARM64_ADDR64)
		} else {
			out.Write16(ld.IMAGE_REL_ARM64_ADDR32)
		}

	case objabi.R_PEIMAGEOFF:
		out.Write16(ld.IMAGE_REL_ARM64_ADDR32NB)

	case objabi.R_ADDRARM64:
		// Note: r.Xadd has been taken care of below, in archreloc.
		out.Write32(uint32(sectoff))
		out.Write32(uint32(symdynid))
		out.Write16(ld.IMAGE_REL_ARM64_PAGEBASE_REL21)

		out.Write32(uint32(sectoff + 4))
		out.Write32(uint32(symdynid))
		out.Write16(ld.IMAGE_REL_ARM64_PAGEOFFSET_12A)

	case objabi.R_ARM64_PCREL_LDST8,
		objabi.R_ARM64_PCREL_LDST16,
		objabi.R_ARM64_PCREL_LDST32,
		objabi.R_ARM64_PCREL_LDST64:
		// Note: r.Xadd has been taken care of below, in archreloc.
		out.Write32(uint32(sectoff))
		out.Write32(uint32(symdynid))
		out.Write16(ld.IMAGE_REL_ARM64_PAGEBASE_REL21)

		out.Write32(uint32(sectoff + 4))
		out.Write32(uint32(symdynid))
		out.Write16(ld.IMAGE_REL_ARM64_PAGEOFFSET_12L)

	case objabi.R_CALLARM64:
		// Note: r.Xadd has been taken care of above, by using a label pointing into the middle of the function.
		out.Write32(uint32(sectoff))
		out.Write32(uint32(symdynid))
		out.Write16(ld.IMAGE_REL_ARM64_BRANCH26)
	}

	return true
}

func archreloc(target *ld.Target, ldr *loader.Loader, syms *ld.ArchSyms, r loader.Reloc, s loader.Sym, val int64) (int64, int, bool) {
	const noExtReloc = 0
	const isOk = true

	rs := r.Sym()

	if target.IsExternal() {
		nExtReloc := 0
		switch rt := r.Type(); rt {
		default:
		case objabi.R_ARM64_GOTPCREL,
			objabi.R_ARM64_PCREL_LDST8,
			objabi.R_ARM64_PCREL_LDST16,
			objabi.R_ARM64_PCREL_LDST32,
			objabi.R_ARM64_PCREL_LDST64,
			objabi.R_ADDRARM64:

			// set up addend for eventual relocation via outer symbol.
			rs, off := ld.FoldSubSymbolOffset(ldr, rs)
			xadd := r.Add() + off
			rst := ldr.SymType(rs)
			if rst != sym.SHOSTOBJ && rst != sym.SDYNIMPORT && ldr.SymSect(rs) == nil {
				ldr.Errorf(s, "missing section for %s", ldr.SymName(rs))
			}

			nExtReloc = 2 // need two ELF/Mach-O relocations. see elfreloc1/machoreloc1
			if target.IsDarwin() && xadd != 0 {
				nExtReloc = 4 // need another two relocations for non-zero addend
			}

			if target.IsWindows() {
				var o0, o1 uint32
				if target.IsBigEndian() {
					o0 = uint32(val >> 32)
					o1 = uint32(val)
				} else {
					o0 = uint32(val)
					o1 = uint32(val >> 32)
				}

				// The first instruction (ADRP) has a 21-bit immediate field,
				// and the second (ADD or LD/ST) has a 12-bit immediate field.
				// The first instruction is only for high bits, but to get the carry bits right we have
				// to put the full addend, including the bottom 12 bits again.
				// That limits the distance of any addend to only 21 bits.
				// But we assume that ADRP's top bit will be interpreted as a sign bit,
				// so we only use 20 bits.
				// pereloc takes care of introducing new symbol labels
				// every megabyte for longer relocations.
				xadd := uint32(xadd)
				o0 |= (xadd&3)<<29 | (xadd&0xffffc)<<3
				switch rt {
				case objabi.R_ARM64_PCREL_LDST8, objabi.R_ADDRARM64:
					o1 |= (xadd & 0xfff) << 10
				case objabi.R_ARM64_PCREL_LDST16:
					if xadd&0x1 != 0 {
						ldr.Errorf(s, "offset for 16-bit load/store has unaligned value %d", xadd&0xfff)
					}
					o1 |= ((xadd & 0xfff) >> 1) << 10
				case objabi.R_ARM64_PCREL_LDST32:
					if xadd&0x3 != 0 {
						ldr.Errorf(s, "offset for 32-bit load/store has unaligned value %d", xadd&0xfff)
					}
					o1 |= ((xadd & 0xfff) >> 2) << 10
				case objabi.R_ARM64_PCREL_LDST64:
					if xadd&0x7 != 0 {
						ldr.Errorf(s, "offset for 64-bit load/store has unaligned value %d", xadd&0xfff)
					}
					o1 |= ((xadd & 0xfff) >> 3) << 10
				}

				if target.IsBigEndian() {
					val = int64(o0)<<32 | int64(o1)
				} else {
					val = int64(o1)<<32 | int64(o0)
				}
			}

			return val, nExtReloc, isOk

		case objabi.R_CALLARM64:
			nExtReloc = 1
			return val, nExtReloc, isOk

		case objabi.R_ARM64_TLS_LE:
			nExtReloc = 1
			return val, nExtReloc, isOk

		case objabi.R_ARM64_TLS_IE:
			nExtReloc = 2 // need two ELF relocations. see elfreloc1
			return val, nExtReloc, isOk

		case objabi.R_ADDR:
			if target.IsWindows() && r.Add() != 0 {
				if r.Siz() == 8 {
					val = r.Add()
				} else if target.IsBigEndian() {
					val = int64(uint32(val)) | int64(r.Add())<<32
				} else {
					val = val>>32<<32 | int64(uint32(r.Add()))
				}
				return val, 1, true
			}
		}
	}

	switch rt := r.Type(); rt {
	case objabi.R_ADDRARM64,
		objabi.R_ARM64_PCREL_LDST8,
		objabi.R_ARM64_PCREL_LDST16,
		objabi.R_ARM64_PCREL_LDST32,
		objabi.R_ARM64_PCREL_LDST64:
		t := ldr.SymAddr(rs) + r.Add() - ((ldr.SymValue(s) + int64(r.Off())) &^ 0xfff)
		if t >= 1<<32 || t < -1<<32 {
			ldr.Errorf(s, "program too large, address relocation distance = %d", t)
		}

		var o0, o1 uint32

		if target.IsBigEndian() {
			o0 = uint32(val >> 32)
			o1 = uint32(val)
		} else {
			o0 = uint32(val)
			o1 = uint32(val >> 32)
		}

		o0 |= (uint32((t>>12)&3) << 29) | (uint32((t>>12>>2)&0x7ffff) << 5)
		switch rt {
		case objabi.R_ARM64_PCREL_LDST8, objabi.R_ADDRARM64:
			o1 |= uint32(t&0xfff) << 10
		case objabi.R_ARM64_PCREL_LDST16:
			if t&0x1 != 0 {
				ldr.Errorf(s, "offset for 16-bit load/store has unaligned value %d", t&0xfff)
			}
			o1 |= (uint32(t&0xfff) >> 1) << 10
		case objabi.R_ARM64_PCREL_LDST32:
			if t&0x3 != 0 {
				ldr.Errorf(s, "offset for 32-bit load/store has unaligned value %d", t&0xfff)
			}
			o1 |= (uint32(t&0xfff) >> 2) << 10
		case objabi.R_ARM64_PCREL_LDST64:
			if t&0x7 != 0 {
				ldr.Errorf(s, "offset for 64-bit load/store has unaligned value %d", t&0xfff)
			}
			o1 |= (uint32(t&0xfff) >> 3) << 10
		}

		// when laid out, the instruction order must always be o1, o2.
		if target.IsBigEndian() {
			return int64(o0)<<32 | int64(o1), noExtReloc, true
		}
		return int64(o1)<<32 | int64(o0), noExtReloc, true

	case objabi.R_ARM64_TLS_LE:
		if target.IsDarwin() {
			ldr.Errorf(s, "TLS reloc on unsupported OS %v", target.HeadType)
		}
		// The TCB is two pointers. This is not documented anywhere, but is
		// de facto part of the ABI.
		v := ldr.SymValue(rs) + int64(2*target.Arch.PtrSize)
		if v < 0 || v >= 32678 {
			ldr.Errorf(s, "TLS offset out of range %d", v)
		}
		return val | (v << 5), noExtReloc, true

	case objabi.R_ARM64_TLS_IE:
		if target.IsPIE() && target.IsElf() {
			// We are linking the final executable, so we
			// can optimize any TLS IE relocation to LE.

			if !target.IsLinux() {
				ldr.Errorf(s, "TLS reloc on unsupported OS %v", target.HeadType)
			}

			// The TCB is two pointers. This is not documented anywhere, but is
			// de facto part of the ABI.
			v := ldr.SymAddr(rs) + int64(2*target.Arch.PtrSize) + r.Add()
			if v < 0 || v >= 32678 {
				ldr.Errorf(s, "TLS offset out of range %d", v)
			}

			var o0, o1 uint32
			if target.IsBigEndian() {
				o0 = uint32(val >> 32)
				o1 = uint32(val)
			} else {
				o0 = uint32(val)
				o1 = uint32(val >> 32)
			}

			// R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21
			// turn ADRP to MOVZ
			o0 = 0xd2a00000 | uint32(o0&0x1f) | (uint32((v>>16)&0xffff) << 5)
			// R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC
			// turn LD64 to MOVK
			if v&3 != 0 {
				ldr.Errorf(s, "invalid address: %x for relocation type: R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC", v)
			}
			o1 = 0xf2800000 | uint32(o1&0x1f) | (uint32(v&0xffff) << 5)

			// when laid out, the instruction order must always be o0, o1.
			if target.IsBigEndian() {
				return int64(o0)<<32 | int64(o1), noExtReloc, isOk
			}
			return int64(o1)<<32 | int64(o0), noExtReloc, isOk
		} else {
			log.Fatalf("cannot handle R_ARM64_TLS_IE (sym %s) when linking internally", ldr.SymName(s))
		}

	case objabi.R_CALLARM64:
		var t int64
		if ldr.SymType(rs) == sym.SDYNIMPORT {
			t = (ldr.SymAddr(syms.PLT) + r.Add()) - (ldr.SymValue(s) + int64(r.Off()))
		} else {
			t = (ldr.SymAddr(rs) + r.Add()) - (ldr.SymValue(s) + int64(r.Off()))
		}
		if t >= 1<<27 || t < -1<<27 {
			ldr.Errorf(s, "program too large, call relocation distance = %d", t)
		}
		return val | ((t >> 2) & 0x03ffffff), noExtReloc, true

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