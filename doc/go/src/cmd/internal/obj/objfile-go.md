Response: Let's break down the thought process for analyzing this Go code.

1. **Initial Scan for Keywords and Structure:** I'd first quickly scan the code for obvious keywords and structural elements:
    * `package obj`:  Tells us the package name and its general domain. This suggests it's related to object files.
    * `import`: Lists dependencies, giving hints about related functionalities (e.g., `cmd/internal/bio` for buffered I/O, `cmd/internal/goobj` for a Go object file format, `cmd/internal/objabi` for object file ABI details).
    * Function names like `WriteObjFile`, `StringTable`, `Sym`, `Reloc`, `Aux`, `Hash`, `refFlags`, `refNames`. These are strong indicators of the core operations.
    * Data structures like `writer`, `LSym`, `Reloc`. Understanding these is crucial.
    * Constants like `UnlinkablePkg` and `cutoff`.

2. **Focus on the Core Function: `WriteObjFile`:** This function is explicitly mentioned as the "Entry point of writing new object file."  This is where the main logic will reside. I would examine its steps sequentially:
    * `debugAsmEmit(ctxt)` and `genFuncInfoSyms(ctxt)`:  These are helper functions called early, suggesting debugging and function information generation are initial steps.
    * Initialization of the `writer` struct: This struct seems to encapsulate the state and methods for writing the object file. The fields like `Writer`, `ctxt`, `pkgpath` are important.
    * Writing the `goobj.Header`: This immediately tells us the code deals with a specific, structured object file format. The header contains essential metadata.
    * Subsequent calls like `w.StringTable()`, `h.Offsets[goobj.BlkAutolib] = w.Offset()`, followed by loops writing different kinds of data (imports, packages, files, symbols, relocations, etc.). This reveals the structure of the object file. The `h.Offsets` array suggests a block-based structure with offsets stored in the header.

3. **Inferring the Purpose:** Based on the structure of `WriteObjFile` and the names of the blocks (`BlkAutolib`, `BlkPkgIdx`, `BlkSymdef`, `BlkReloc`, etc.), it becomes clear that this code is responsible for *serializing Go compilation output into a specific object file format*. This format likely contains all the necessary information for the linker to combine multiple object files and produce an executable.

4. **Deeper Dive into Key Functions:** Now, I'd look into some of the important helper functions:
    * `StringTable`: This is likely responsible for creating a table of strings used in the object file to avoid redundancy.
    * `Sym`:  Handles writing information about a single symbol (`LSym`). The flags (`SymFlagDupok`, `SymFlagLocal`, etc.) are important for understanding symbol properties.
    * `Reloc`:  Writes relocation information, which is crucial for the linker to resolve addresses.
    * `Aux`: Writes auxiliary symbol information, often related to debugging or metadata.
    * `Hash` and `Hash64`: These are for generating content hashes, likely used for deduplication or content-addressable storage of symbols.

5. **Connecting to Go Concepts:**  Now, I'd start linking the code to my understanding of Go:
    * **Packages and Imports:** The code clearly handles package paths and imports, essential concepts in Go.
    * **Symbols:**  The concept of symbols (functions, variables, types) is central to linking. The code writes information about these symbols.
    * **Relocations:**  Go's compilation and linking process involves relocations to handle address dependencies.
    * **Object Files:**  The code's purpose is explicitly to write these files, which are intermediate outputs of the compiler.
    * **Debugging Information (DWARF):** The presence of `dwarfInfoSym`, `dwarfLocSym`, etc., indicates support for generating debugging information.
    * **Function Metadata:**  The handling of `FuncInfo`, `Pcln` (program counter line information), and inline trees relates to function-specific metadata needed for debugging, stack unwinding, etc.

6. **Crafting Examples and Explanations:** With a solid understanding of the code's function, I would construct examples. Since the code writes object files, the most relevant Go feature is the compilation process itself. A simple `go build` command demonstrates the use case. For code examples related to specific functionalities like relocations or symbol flags, it's harder to provide direct Go code that *uses* this `objfile.go` directly. Instead, the example shows the *effect* of what this code produces during compilation. Explaining the command-line arguments involves looking for flags that influence the object file output (though this specific file doesn't directly parse them; that happens earlier in the compilation process).

7. **Identifying Potential Pitfalls:**  Finally, I would think about common errors developers make related to the *output* of this code (object files) or the compilation process it's a part of. Forgetting to import packages, having name collisions, or issues with C interoperability are potential problems that manifest during linking, which operates on the object files generated by this code.

8. **Refinement and Structure:** I'd organize my findings logically, starting with the high-level functionality, then drilling down into specifics, providing code examples, explaining command-line arguments (even if indirect), and finally, pointing out potential errors. Using clear headings and formatting improves readability.

This iterative process of scanning, focusing, inferring, connecting, exemplifying, and refining allows for a comprehensive understanding of the code's purpose and its place within the larger Go toolchain. Even without deep prior knowledge of the `cmd/internal` packages, the code itself provides significant clues.
这段代码是 Go 编译器的一部分，位于 `go/src/cmd/internal/obj/objfile.go`，它的主要功能是**将编译后的 Go 代码的中间表示（internal representation）写入到目标文件（object file）中**。这个目标文件通常是 `.o` 文件，会被链接器（linker）进一步处理生成最终的可执行文件或库文件。

让我们更详细地分解它的功能和相关的 Go 语言特性：

**1. 核心功能：写入目标文件**

`WriteObjFile` 函数是写入目标文件的入口点。它接收一个 `*Link` 上下文和一个 `*bio.Writer` 作为参数。

*   **`*Link` ctxt:**  这个上下文包含了编译过程中的所有信息，例如符号表、类型信息、导入的包、命令行参数等等。
*   **`*bio.Writer` b:**  这是一个用于高效写入缓冲数据的 Writer，它会将数据写入到实际的文件中。

`WriteObjFile` 函数的主要步骤如下：

*   **初始化 `writer` 结构体:**  `writer` 结构体封装了写入目标文件所需的状态和方法，例如当前写入的偏移量、包路径等。
*   **写入文件头 (Header):**  包含魔数（Magic）、指纹（Fingerprint）、标志位（Flags）等元数据，用于标识这是一个 Go 的目标文件。
*   **写入字符串表 (String Table):**  存储了目标文件中用到的所有字符串，例如符号名、包名、文件名等，以减少重复存储。
*   **写入自动链接库 (Autolib):**  记录了需要自动链接的库信息。
*   **写入包引用 (Package References):**  列出了当前目标文件引用的其他 Go 包。
*   **写入文件表 (File Table):**  记录了源代码文件的路径，用于调试信息和 `pcln`（program counter line number）表的生成。
*   **写入符号定义 (Symbol Definitions):**  这是目标文件的核心部分，包含了当前编译单元中定义的所有符号的信息，例如函数、变量、类型等。根据符号的不同属性（是否被哈希），会写入到不同的块中 (`BlkSymdef`, `BlkHashed64def`, `BlkHasheddef`, `BlkNonpkgdef`)。
*   **写入非包符号引用 (Non-pkg Symbol References):**  记录了引用的不属于任何 Go 包的符号，例如 C 语言的函数或全局变量。
*   **写入引用的包符号标志 (Referenced Package Symbol Flags):**  记录了引用的其他包中符号的特定标志。
*   **写入哈希值 (Hashes):**  对于内容可寻址的符号（Content Addressable），会计算并写入其内容的哈希值，用于链接时的重复数据删除。
*   **写入重定位索引 (Reloc Indexes):**  记录了每个符号的重定位信息在 `BlkReloc` 块中的起始位置和数量。
*   **写入符号信息索引 (Symbol Info Indexes):** 记录了每个符号的辅助信息（例如，函数信息，DWARF 调试信息）在 `BlkAux` 块中的起始位置和数量。
*   **写入数据索引 (Data Indexes):**  记录了每个符号的数据在 `BlkData` 块中的偏移量。
*   **写入重定位信息 (Relocs):**  包含了需要链接器处理的重定位信息，例如函数调用、全局变量访问等，需要将占位符地址替换为实际地址。
*   **写入辅助符号信息 (Aux Symbol Info):**  存储了与符号相关的额外信息，例如：
    *   `Gotype`:  符号对应的 Go 类型信息。
    *   `FuncInfo`:  函数的参数、局部变量大小、函数标志等信息。
    *   DWARF 调试信息相关的符号（`DwarfInfo`, `DwarfLoc`, `DwarfRanges`, `DwarfLines`）。
    *   `Pcln` 表相关的符号 (`Pcsp`, `Pcfile`, `Pcline`, `Pcinline`)。
    *   SEH 异常处理信息 (`SehUnwindInfo`).
    *   函数数据 (`Funcdata`)。
    *   WASM 导入/导出信息 (`WasmImport`, `WasmExport`).
*   **写入数据 (Data):**  包含了符号的实际数据，例如全局变量的初始值、字符串字面量等。
*   **写入引用的符号名称 (Referenced Symbol Names):**  记录了引用的其他包中的符号名称，主要用于工具（如 `objdump`, `nm`）。
*   **更新文件头偏移量:**  在所有数据块写入完成后，将各个块的起始偏移量写回到文件头中。

**2. 涉及的 Go 语言功能**

这段代码的实现涉及到 Go 语言的多个核心功能：

*   **编译过程:**  这是 Go 语言编译器的内部实现，负责将 Go 源代码转换为机器码。
*   **目标文件格式:**  定义了 Go 语言的 `.o` 文件的结构，包括头部、字符串表、符号表、重定位信息等。
*   **链接 (Linking):**  目标文件是链接器的输入，链接器会将多个目标文件合并成一个可执行文件或库文件。
*   **符号 (Symbols):**  程序中的函数、变量、类型等都被抽象为符号，链接器通过符号来解析跨模块的引用。
*   **重定位 (Relocation):**  由于编译时无法确定所有符号的最终地址，需要在目标文件中记录重定位信息，以便链接器在链接时进行地址修正。
*   **调试信息 (DWARF):**  用于支持调试器，包含了源代码的行号、变量信息等。
*   **`go build` 命令:**  `go build` 命令会调用编译器，最终会使用到这段代码来生成目标文件。
*   **内部包 (`cmd/internal`)**:  这段代码位于 `cmd/internal` 目录下，表明它是 Go 工具链的内部实现细节，通常不建议外部直接使用。

**3. 代码示例**

虽然我们不能直接调用 `WriteObjFile` 函数，但可以通过 `go build` 命令来观察它生成目标文件的过程。

**假设有以下 Go 代码 `main.go`:**

```go
package main

import "fmt"

var globalVar int = 10

func main() {
	fmt.Println("Hello, world!", globalVar)
}
```

**使用 `go build -gcflags=-S main.go` 命令（输出汇编代码，会触发目标文件的生成）：**

虽然这里没有直接输出 `.o` 文件，但是编译过程内部会调用 `objfile.go` 中的代码来生成目标文件，然后再由链接器处理。

我们可以通过查看编译器的内部步骤来更清楚地理解：

```bash
go build -n main.go
```

这个命令会打印出实际执行的命令，其中会包含生成目标文件的步骤（具体命令会因 Go 版本和操作系统而异）。你可能会看到类似这样的命令：

```
/path/to/ компилятор/компилятор -o _obj/./main.o ... main.go
```

这里的 `_obj/./main.o` 就是由 `objfile.go` 生成的目标文件。

**4. 命令行参数的具体处理**

`WriteObjFile` 函数本身不直接处理命令行参数。命令行参数的处理发生在编译过程的更早阶段，例如在 `cmd/compile/internal/gc` 包中。这些参数会影响 `*Link` 上下文中的信息，从而间接地影响 `WriteObjFile` 的行为。

例如：

*   **`-p <package path>`:**  指定编译的包路径，会影响 `w.pkgpath` 的值。
*   **`-shared`:**  生成共享库，会设置 `ctxt.Flag_shared`，从而影响目标文件的标志位 (`goobj.ObjFlagShared`)。
*   **`-std`:**  编译标准库，会设置 `ctxt.Std`，从而影响目标文件的标志位 (`goobj.ObjFlagStd`)。
*   **`-gcflags`:**  可以传递给 Go 编译器的标志，例如 `-S` 输出汇编代码，这会触发目标文件的生成。

**5. 使用者易犯错的点**

由于 `objfile.go` 是 Go 编译器的内部实现，普通 Go 开发者通常不会直接与其交互，因此直接犯错的机会不多。但是，了解它的工作原理有助于理解编译和链接过程，从而避免一些间接的错误：

*   **不理解目标文件的作用：**  可能导致对编译和链接过程的理解不足，例如，不明白为什么需要链接器，或者为什么修改了一个包的代码需要重新编译依赖它的包。
*   **错误地配置链接器参数：**  虽然 `objfile.go` 不直接处理链接器参数，但它生成的目标文件是链接器的输入，如果链接器参数配置错误，例如缺少必要的库，会导致链接失败。
*   **对符号可见性理解不足：**  目标文件中符号的导出和导入规则直接影响链接过程，不理解这些规则可能导致链接错误，例如 "undefined symbol" 错误。

**总结**

`go/src/cmd/internal/obj/objfile.go` 是 Go 编译器中至关重要的一个文件，它负责将编译后的代码结构化地写入到目标文件中。理解它的功能有助于深入了解 Go 语言的编译和链接过程，虽然开发者通常不会直接使用它，但理解其原理可以帮助更好地理解 Go 语言的底层机制。

### 提示词
```
这是路径为go/src/cmd/internal/obj/objfile.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Writing Go object files.

package obj

import (
	"bytes"
	"cmd/internal/bio"
	"cmd/internal/goobj"
	"cmd/internal/hash"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"cmp"
	"encoding/binary"
	"fmt"
	"internal/abi"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

const UnlinkablePkg = "<unlinkable>" // invalid package path, used when compiled without -p flag

// Entry point of writing new object file.
func WriteObjFile(ctxt *Link, b *bio.Writer) {

	debugAsmEmit(ctxt)

	genFuncInfoSyms(ctxt)

	w := writer{
		Writer:  goobj.NewWriter(b),
		ctxt:    ctxt,
		pkgpath: objabi.PathToPrefix(ctxt.Pkgpath),
	}

	start := b.Offset()
	w.init()

	// Header
	// We just reserve the space. We'll fill in the offsets later.
	flags := uint32(0)
	if ctxt.Flag_shared {
		flags |= goobj.ObjFlagShared
	}
	if w.pkgpath == UnlinkablePkg {
		flags |= goobj.ObjFlagUnlinkable
	}
	if w.pkgpath == "" {
		log.Fatal("empty package path")
	}
	if ctxt.IsAsm {
		flags |= goobj.ObjFlagFromAssembly
	}
	if ctxt.Std {
		flags |= goobj.ObjFlagStd
	}
	h := goobj.Header{
		Magic:       goobj.Magic,
		Fingerprint: ctxt.Fingerprint,
		Flags:       flags,
	}
	h.Write(w.Writer)

	// String table
	w.StringTable()

	// Autolib
	h.Offsets[goobj.BlkAutolib] = w.Offset()
	for i := range ctxt.Imports {
		ctxt.Imports[i].Write(w.Writer)
	}

	// Package references
	h.Offsets[goobj.BlkPkgIdx] = w.Offset()
	for _, pkg := range w.pkglist {
		w.StringRef(pkg)
	}

	// File table (for DWARF and pcln generation).
	h.Offsets[goobj.BlkFile] = w.Offset()
	for _, f := range ctxt.PosTable.FileTable() {
		w.StringRef(filepath.ToSlash(f))
	}

	// Symbol definitions
	h.Offsets[goobj.BlkSymdef] = w.Offset()
	for _, s := range ctxt.defs {
		w.Sym(s)
	}

	// Short hashed symbol definitions
	h.Offsets[goobj.BlkHashed64def] = w.Offset()
	for _, s := range ctxt.hashed64defs {
		w.Sym(s)
	}

	// Hashed symbol definitions
	h.Offsets[goobj.BlkHasheddef] = w.Offset()
	for _, s := range ctxt.hasheddefs {
		w.Sym(s)
	}

	// Non-pkg symbol definitions
	h.Offsets[goobj.BlkNonpkgdef] = w.Offset()
	for _, s := range ctxt.nonpkgdefs {
		w.Sym(s)
	}

	// Non-pkg symbol references
	h.Offsets[goobj.BlkNonpkgref] = w.Offset()
	for _, s := range ctxt.nonpkgrefs {
		w.Sym(s)
	}

	// Referenced package symbol flags
	h.Offsets[goobj.BlkRefFlags] = w.Offset()
	w.refFlags()

	// Hashes
	h.Offsets[goobj.BlkHash64] = w.Offset()
	for _, s := range ctxt.hashed64defs {
		w.Hash64(s)
	}
	h.Offsets[goobj.BlkHash] = w.Offset()
	for _, s := range ctxt.hasheddefs {
		w.Hash(s)
	}
	// TODO: hashedrefs unused/unsupported for now

	// Reloc indexes
	h.Offsets[goobj.BlkRelocIdx] = w.Offset()
	nreloc := uint32(0)
	lists := [][]*LSym{ctxt.defs, ctxt.hashed64defs, ctxt.hasheddefs, ctxt.nonpkgdefs}
	for _, list := range lists {
		for _, s := range list {
			w.Uint32(nreloc)
			nreloc += uint32(len(s.R))
		}
	}
	w.Uint32(nreloc)

	// Symbol Info indexes
	h.Offsets[goobj.BlkAuxIdx] = w.Offset()
	naux := uint32(0)
	for _, list := range lists {
		for _, s := range list {
			w.Uint32(naux)
			naux += uint32(nAuxSym(s))
		}
	}
	w.Uint32(naux)

	// Data indexes
	h.Offsets[goobj.BlkDataIdx] = w.Offset()
	dataOff := int64(0)
	for _, list := range lists {
		for _, s := range list {
			w.Uint32(uint32(dataOff))
			dataOff += int64(len(s.P))
			if file := s.File(); file != nil {
				dataOff += int64(file.Size)
			}
		}
	}
	if int64(uint32(dataOff)) != dataOff {
		log.Fatalf("data too large")
	}
	w.Uint32(uint32(dataOff))

	// Relocs
	h.Offsets[goobj.BlkReloc] = w.Offset()
	for _, list := range lists {
		for _, s := range list {
			slices.SortFunc(s.R, relocByOffCmp) // some platforms (e.g. PE) requires relocations in address order
			for i := range s.R {
				w.Reloc(&s.R[i])
			}
		}
	}

	// Aux symbol info
	h.Offsets[goobj.BlkAux] = w.Offset()
	for _, list := range lists {
		for _, s := range list {
			w.Aux(s)
		}
	}

	// Data
	h.Offsets[goobj.BlkData] = w.Offset()
	for _, list := range lists {
		for _, s := range list {
			w.Bytes(s.P)
			if file := s.File(); file != nil {
				w.writeFile(ctxt, file)
			}
		}
	}

	// Blocks used only by tools (objdump, nm).

	// Referenced symbol names from other packages
	h.Offsets[goobj.BlkRefName] = w.Offset()
	w.refNames()

	h.Offsets[goobj.BlkEnd] = w.Offset()

	// Fix up block offsets in the header
	end := start + int64(w.Offset())
	b.MustSeek(start, 0)
	h.Write(w.Writer)
	b.MustSeek(end, 0)
}

type writer struct {
	*goobj.Writer
	filebuf []byte
	ctxt    *Link
	pkgpath string   // the package import path (escaped), "" if unknown
	pkglist []string // list of packages referenced, indexed by ctxt.pkgIdx

	// scratch space for writing (the Write methods escape
	// as they are interface calls)
	tmpSym      goobj.Sym
	tmpReloc    goobj.Reloc
	tmpAux      goobj.Aux
	tmpHash64   goobj.Hash64Type
	tmpHash     goobj.HashType
	tmpRefFlags goobj.RefFlags
	tmpRefName  goobj.RefName
}

// prepare package index list
func (w *writer) init() {
	w.pkglist = make([]string, len(w.ctxt.pkgIdx)+1)
	w.pkglist[0] = "" // dummy invalid package for index 0
	for pkg, i := range w.ctxt.pkgIdx {
		w.pkglist[i] = pkg
	}
}

func (w *writer) writeFile(ctxt *Link, file *FileInfo) {
	f, err := os.Open(file.Name)
	if err != nil {
		ctxt.Diag("%v", err)
		return
	}
	defer f.Close()
	if w.filebuf == nil {
		w.filebuf = make([]byte, 1024)
	}
	buf := w.filebuf
	written := int64(0)
	for {
		n, err := f.Read(buf)
		w.Bytes(buf[:n])
		written += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			ctxt.Diag("%v", err)
			return
		}
	}
	if written != file.Size {
		ctxt.Diag("copy %s: unexpected length %d != %d", file.Name, written, file.Size)
	}
}

func (w *writer) StringTable() {
	w.AddString("")
	for _, p := range w.ctxt.Imports {
		w.AddString(p.Pkg)
	}
	for _, pkg := range w.pkglist {
		w.AddString(pkg)
	}
	w.ctxt.traverseSyms(traverseAll, func(s *LSym) {
		// Don't put names of builtins into the string table (to save
		// space).
		if s.PkgIdx == goobj.PkgIdxBuiltin {
			return
		}
		// TODO: this includes references of indexed symbols from other packages,
		// for which the linker doesn't need the name. Consider moving them to
		// a separate block (for tools only).
		if w.ctxt.Flag_noRefName && s.PkgIdx < goobj.PkgIdxSpecial {
			// Don't include them if Flag_noRefName
			return
		}
		if strings.HasPrefix(s.Name, `"".`) {
			w.ctxt.Diag("unqualified symbol name: %v", s.Name)
		}
		w.AddString(s.Name)
	})

	// All filenames are in the postable.
	for _, f := range w.ctxt.PosTable.FileTable() {
		w.AddString(filepath.ToSlash(f))
	}
}

// cutoff is the maximum data section size permitted by the linker
// (see issue #9862).
const cutoff = int64(2e9) // 2 GB (or so; looks better in errors than 2^31)

func (w *writer) Sym(s *LSym) {
	name := s.Name
	abi := uint16(s.ABI())
	if s.Static() {
		abi = goobj.SymABIstatic
	}
	flag := uint8(0)
	if s.DuplicateOK() {
		flag |= goobj.SymFlagDupok
	}
	if s.Local() {
		flag |= goobj.SymFlagLocal
	}
	if s.MakeTypelink() {
		flag |= goobj.SymFlagTypelink
	}
	if s.Leaf() {
		flag |= goobj.SymFlagLeaf
	}
	if s.NoSplit() {
		flag |= goobj.SymFlagNoSplit
	}
	if s.ReflectMethod() {
		flag |= goobj.SymFlagReflectMethod
	}
	if strings.HasPrefix(s.Name, "type:") && s.Name[5] != '.' && s.Type == objabi.SRODATA {
		flag |= goobj.SymFlagGoType
	}
	flag2 := uint8(0)
	if s.UsedInIface() {
		flag2 |= goobj.SymFlagUsedInIface
	}
	if strings.HasPrefix(s.Name, "go:itab.") && s.Type == objabi.SRODATA {
		flag2 |= goobj.SymFlagItab
	}
	if strings.HasPrefix(s.Name, w.ctxt.Pkgpath) && strings.HasPrefix(s.Name[len(w.ctxt.Pkgpath):], ".") && strings.HasPrefix(s.Name[len(w.ctxt.Pkgpath)+1:], objabi.GlobalDictPrefix) {
		flag2 |= goobj.SymFlagDict
	}
	if s.IsPkgInit() {
		flag2 |= goobj.SymFlagPkgInit
	}
	if s.IsLinkname() || (w.ctxt.IsAsm && name != "") || name == "main.main" {
		// Assembly reference is treated the same as linkname,
		// but not for unnamed (aux) symbols.
		// The runtime linknames main.main.
		flag2 |= goobj.SymFlagLinkname
	}
	if s.ABIWrapper() {
		flag2 |= goobj.SymFlagABIWrapper
	}
	if s.Func() != nil && s.Func().WasmExport != nil {
		flag2 |= goobj.SymFlagWasmExport
	}
	if strings.HasPrefix(name, "gofile..") {
		name = filepath.ToSlash(name)
	}
	var align uint32
	if fn := s.Func(); fn != nil {
		align = uint32(fn.Align)
	}
	if s.ContentAddressable() && s.Size != 0 {
		// We generally assume data symbols are naturally aligned
		// (e.g. integer constants), except for strings and a few
		// compiler-emitted funcdata. If we dedup a string symbol and
		// a non-string symbol with the same content, we should keep
		// the largest alignment.
		// TODO: maybe the compiler could set the alignment for all
		// data symbols more carefully.
		switch {
		case strings.HasPrefix(s.Name, "go:string."),
			strings.HasPrefix(name, "type:.namedata."),
			strings.HasPrefix(name, "type:.importpath."),
			strings.HasSuffix(name, ".opendefer"),
			strings.HasSuffix(name, ".arginfo0"),
			strings.HasSuffix(name, ".arginfo1"),
			strings.HasSuffix(name, ".argliveinfo"):
			// These are just bytes, or varints.
			align = 1
		case strings.HasPrefix(name, "gclocals·"):
			// It has 32-bit fields.
			align = 4
		default:
			switch {
			case w.ctxt.Arch.PtrSize == 8 && s.Size%8 == 0:
				align = 8
			case s.Size%4 == 0:
				align = 4
			case s.Size%2 == 0:
				align = 2
			default:
				align = 1
			}
		}
	}
	if s.Size > cutoff {
		w.ctxt.Diag("%s: symbol too large (%d bytes > %d bytes)", s.Name, s.Size, cutoff)
	}
	o := &w.tmpSym
	o.SetName(name, w.Writer)
	o.SetABI(abi)
	o.SetType(uint8(s.Type))
	o.SetFlag(flag)
	o.SetFlag2(flag2)
	o.SetSiz(uint32(s.Size))
	o.SetAlign(align)
	o.Write(w.Writer)
}

func (w *writer) Hash64(s *LSym) {
	if !s.ContentAddressable() || len(s.R) != 0 {
		panic("Hash of non-content-addressable symbol")
	}
	w.tmpHash64 = contentHash64(s)
	w.Bytes(w.tmpHash64[:])
}

func (w *writer) Hash(s *LSym) {
	if !s.ContentAddressable() {
		panic("Hash of non-content-addressable symbol")
	}
	w.tmpHash = w.contentHash(s)
	w.Bytes(w.tmpHash[:])
}

// contentHashSection returns a mnemonic for s's section.
// The goal is to prevent content-addressability from moving symbols between sections.
// contentHashSection only distinguishes between sets of sections for which this matters.
// Allowing flexibility increases the effectiveness of content-addressability.
// But in some cases, such as doing addressing based on a base symbol,
// we need to ensure that a symbol is always in a particular section.
// Some of these conditions are duplicated in cmd/link/internal/ld.(*Link).symtab.
// TODO: instead of duplicating them, have the compiler decide where symbols go.
func contentHashSection(s *LSym) byte {
	name := s.Name
	if s.IsPcdata() {
		return 'P'
	}
	if strings.HasPrefix(name, "gcargs.") ||
		strings.HasPrefix(name, "gclocals.") ||
		strings.HasPrefix(name, "gclocals·") ||
		strings.HasSuffix(name, ".opendefer") ||
		strings.HasSuffix(name, ".arginfo0") ||
		strings.HasSuffix(name, ".arginfo1") ||
		strings.HasSuffix(name, ".argliveinfo") ||
		strings.HasSuffix(name, ".wrapinfo") ||
		strings.HasSuffix(name, ".args_stackmap") ||
		strings.HasSuffix(name, ".stkobj") {
		return 'F' // go:func.* or go:funcrel.*
	}
	if strings.HasPrefix(name, "type:") {
		return 'T'
	}
	return 0
}

func contentHash64(s *LSym) goobj.Hash64Type {
	if contentHashSection(s) != 0 {
		panic("short hash of non-default-section sym " + s.Name)
	}
	var b goobj.Hash64Type
	copy(b[:], s.P)
	return b
}

// Compute the content hash for a content-addressable symbol.
// We build a content hash based on its content and relocations.
// Depending on the category of the referenced symbol, we choose
// different hash algorithms such that the hash is globally
// consistent.
//   - For referenced content-addressable symbol, its content hash
//     is globally consistent.
//   - For package symbol and builtin symbol, its local index is
//     globally consistent.
//   - For non-package symbol, its fully-expanded name is globally
//     consistent. For now, we require we know the current package
//     path so we can always expand symbol names. (Otherwise,
//     symbols with relocations are not considered hashable.)
//
// For now, we assume there is no circular dependencies among
// hashed symbols.
func (w *writer) contentHash(s *LSym) goobj.HashType {
	h := hash.New20()
	var tmp [14]byte

	// Include the size of the symbol in the hash.
	// This preserves the length of symbols, preventing the following two symbols
	// from hashing the same:
	//
	//    [2]int{1,2} ≠ [10]int{1,2,0,0,0...}
	//
	// In this case, if the smaller symbol is alive, the larger is not kept unless
	// needed.
	binary.LittleEndian.PutUint64(tmp[:8], uint64(s.Size))
	// Some symbols require being in separate sections.
	tmp[8] = contentHashSection(s)
	h.Write(tmp[:9])

	// The compiler trims trailing zeros _sometimes_. We just do
	// it always.
	h.Write(bytes.TrimRight(s.P, "\x00"))
	for i := range s.R {
		r := &s.R[i]
		binary.LittleEndian.PutUint32(tmp[:4], uint32(r.Off))
		tmp[4] = r.Siz
		tmp[5] = uint8(r.Type)
		binary.LittleEndian.PutUint64(tmp[6:14], uint64(r.Add))
		h.Write(tmp[:])
		rs := r.Sym
		if rs == nil {
			fmt.Printf("symbol: %s\n", s)
			fmt.Printf("relocation: %#v\n", r)
			panic("nil symbol target in relocation")
		}
		switch rs.PkgIdx {
		case goobj.PkgIdxHashed64:
			h.Write([]byte{0})
			t := contentHash64(rs)
			h.Write(t[:])
		case goobj.PkgIdxHashed:
			h.Write([]byte{1})
			t := w.contentHash(rs)
			h.Write(t[:])
		case goobj.PkgIdxNone:
			h.Write([]byte{2})
			io.WriteString(h, rs.Name) // name is already expanded at this point
		case goobj.PkgIdxBuiltin:
			h.Write([]byte{3})
			binary.LittleEndian.PutUint32(tmp[:4], uint32(rs.SymIdx))
			h.Write(tmp[:4])
		case goobj.PkgIdxSelf:
			io.WriteString(h, w.pkgpath)
			binary.LittleEndian.PutUint32(tmp[:4], uint32(rs.SymIdx))
			h.Write(tmp[:4])
		default:
			io.WriteString(h, rs.Pkg)
			binary.LittleEndian.PutUint32(tmp[:4], uint32(rs.SymIdx))
			h.Write(tmp[:4])
		}
	}
	var b goobj.HashType
	copy(b[:], h.Sum(nil))
	return b
}

func makeSymRef(s *LSym) goobj.SymRef {
	if s == nil {
		return goobj.SymRef{}
	}
	if s.PkgIdx == 0 || !s.Indexed() {
		fmt.Printf("unindexed symbol reference: %v\n", s)
		panic("unindexed symbol reference")
	}
	return goobj.SymRef{PkgIdx: uint32(s.PkgIdx), SymIdx: uint32(s.SymIdx)}
}

func (w *writer) Reloc(r *Reloc) {
	o := &w.tmpReloc
	o.SetOff(r.Off)
	o.SetSiz(r.Siz)
	o.SetType(uint16(r.Type))
	o.SetAdd(r.Add)
	o.SetSym(makeSymRef(r.Sym))
	o.Write(w.Writer)
}

func (w *writer) aux1(typ uint8, rs *LSym) {
	o := &w.tmpAux
	o.SetType(typ)
	o.SetSym(makeSymRef(rs))
	o.Write(w.Writer)
}

func (w *writer) Aux(s *LSym) {
	if s.Gotype != nil {
		w.aux1(goobj.AuxGotype, s.Gotype)
	}
	if fn := s.Func(); fn != nil {
		w.aux1(goobj.AuxFuncInfo, fn.FuncInfoSym)

		for _, d := range fn.Pcln.Funcdata {
			w.aux1(goobj.AuxFuncdata, d)
		}

		if fn.dwarfInfoSym != nil && fn.dwarfInfoSym.Size != 0 {
			w.aux1(goobj.AuxDwarfInfo, fn.dwarfInfoSym)
		}
		if fn.dwarfLocSym != nil && fn.dwarfLocSym.Size != 0 {
			w.aux1(goobj.AuxDwarfLoc, fn.dwarfLocSym)
		}
		if fn.dwarfRangesSym != nil && fn.dwarfRangesSym.Size != 0 {
			w.aux1(goobj.AuxDwarfRanges, fn.dwarfRangesSym)
		}
		if fn.dwarfDebugLinesSym != nil && fn.dwarfDebugLinesSym.Size != 0 {
			w.aux1(goobj.AuxDwarfLines, fn.dwarfDebugLinesSym)
		}
		if fn.Pcln.Pcsp != nil && fn.Pcln.Pcsp.Size != 0 {
			w.aux1(goobj.AuxPcsp, fn.Pcln.Pcsp)
		}
		if fn.Pcln.Pcfile != nil && fn.Pcln.Pcfile.Size != 0 {
			w.aux1(goobj.AuxPcfile, fn.Pcln.Pcfile)
		}
		if fn.Pcln.Pcline != nil && fn.Pcln.Pcline.Size != 0 {
			w.aux1(goobj.AuxPcline, fn.Pcln.Pcline)
		}
		if fn.Pcln.Pcinline != nil && fn.Pcln.Pcinline.Size != 0 {
			w.aux1(goobj.AuxPcinline, fn.Pcln.Pcinline)
		}
		if fn.sehUnwindInfoSym != nil && fn.sehUnwindInfoSym.Size != 0 {
			w.aux1(goobj.AuxSehUnwindInfo, fn.sehUnwindInfoSym)
		}
		for _, pcSym := range fn.Pcln.Pcdata {
			w.aux1(goobj.AuxPcdata, pcSym)
		}
		if fn.WasmImport != nil {
			if fn.WasmImport.AuxSym.Size == 0 {
				panic("wasmimport aux sym must have non-zero size")
			}
			w.aux1(goobj.AuxWasmImport, fn.WasmImport.AuxSym)
		}
		if fn.WasmExport != nil {
			w.aux1(goobj.AuxWasmType, fn.WasmExport.AuxSym)
		}
	} else if v := s.VarInfo(); v != nil {
		if v.dwarfInfoSym != nil && v.dwarfInfoSym.Size != 0 {
			w.aux1(goobj.AuxDwarfInfo, v.dwarfInfoSym)
		}
	}
}

// Emits flags of referenced indexed symbols.
func (w *writer) refFlags() {
	seen := make(map[*LSym]bool)
	w.ctxt.traverseSyms(traverseRefs, func(rs *LSym) { // only traverse refs, not auxs, as tools don't need auxs
		switch rs.PkgIdx {
		case goobj.PkgIdxNone, goobj.PkgIdxHashed64, goobj.PkgIdxHashed, goobj.PkgIdxBuiltin, goobj.PkgIdxSelf: // not an external indexed reference
			return
		case goobj.PkgIdxInvalid:
			panic("unindexed symbol reference")
		}
		if seen[rs] {
			return
		}
		seen[rs] = true
		symref := makeSymRef(rs)
		flag2 := uint8(0)
		if rs.UsedInIface() {
			flag2 |= goobj.SymFlagUsedInIface
		}
		if flag2 == 0 {
			return // no need to write zero flags
		}
		o := &w.tmpRefFlags
		o.SetSym(symref)
		o.SetFlag2(flag2)
		o.Write(w.Writer)
	})
}

// Emits names of referenced indexed symbols, used by tools (objdump, nm)
// only.
func (w *writer) refNames() {
	if w.ctxt.Flag_noRefName {
		return
	}
	seen := make(map[*LSym]bool)
	w.ctxt.traverseSyms(traverseRefs, func(rs *LSym) { // only traverse refs, not auxs, as tools don't need auxs
		switch rs.PkgIdx {
		case goobj.PkgIdxNone, goobj.PkgIdxHashed64, goobj.PkgIdxHashed, goobj.PkgIdxBuiltin, goobj.PkgIdxSelf: // not an external indexed reference
			return
		case goobj.PkgIdxInvalid:
			panic("unindexed symbol reference")
		}
		if seen[rs] {
			return
		}
		seen[rs] = true
		symref := makeSymRef(rs)
		o := &w.tmpRefName
		o.SetSym(symref)
		o.SetName(rs.Name, w.Writer)
		o.Write(w.Writer)
	})
	// TODO: output in sorted order?
	// Currently tools (cmd/internal/goobj package) doesn't use mmap,
	// and it just read it into a map in memory upfront. If it uses
	// mmap, if the output is sorted, it probably could avoid reading
	// into memory and just do lookups in the mmap'd object file.
}

// return the number of aux symbols s have.
func nAuxSym(s *LSym) int {
	n := 0
	if s.Gotype != nil {
		n++
	}
	if fn := s.Func(); fn != nil {
		// FuncInfo is an aux symbol, each Funcdata is an aux symbol
		n += 1 + len(fn.Pcln.Funcdata)
		if fn.dwarfInfoSym != nil && fn.dwarfInfoSym.Size != 0 {
			n++
		}
		if fn.dwarfLocSym != nil && fn.dwarfLocSym.Size != 0 {
			n++
		}
		if fn.dwarfRangesSym != nil && fn.dwarfRangesSym.Size != 0 {
			n++
		}
		if fn.dwarfDebugLinesSym != nil && fn.dwarfDebugLinesSym.Size != 0 {
			n++
		}
		if fn.Pcln.Pcsp != nil && fn.Pcln.Pcsp.Size != 0 {
			n++
		}
		if fn.Pcln.Pcfile != nil && fn.Pcln.Pcfile.Size != 0 {
			n++
		}
		if fn.Pcln.Pcline != nil && fn.Pcln.Pcline.Size != 0 {
			n++
		}
		if fn.Pcln.Pcinline != nil && fn.Pcln.Pcinline.Size != 0 {
			n++
		}
		if fn.sehUnwindInfoSym != nil && fn.sehUnwindInfoSym.Size != 0 {
			n++
		}
		n += len(fn.Pcln.Pcdata)
		if fn.WasmImport != nil {
			if fn.WasmImport.AuxSym == nil || fn.WasmImport.AuxSym.Size == 0 {
				panic("wasmimport aux sym must exist and have non-zero size")
			}
			n++
		}
		if fn.WasmExport != nil {
			n++
		}
	} else if v := s.VarInfo(); v != nil {
		if v.dwarfInfoSym != nil && v.dwarfInfoSym.Size != 0 {
			n++
		}
	}
	return n
}

// generate symbols for FuncInfo.
func genFuncInfoSyms(ctxt *Link) {
	infosyms := make([]*LSym, 0, len(ctxt.Text))
	var b bytes.Buffer
	symidx := int32(len(ctxt.defs))
	for _, s := range ctxt.Text {
		fn := s.Func()
		if fn == nil {
			continue
		}
		o := goobj.FuncInfo{
			Args:      uint32(fn.Args),
			Locals:    uint32(fn.Locals),
			FuncID:    fn.FuncID,
			FuncFlag:  fn.FuncFlag,
			StartLine: fn.StartLine,
		}
		pc := &fn.Pcln
		i := 0
		o.File = make([]goobj.CUFileIndex, len(pc.UsedFiles))
		for f := range pc.UsedFiles {
			o.File[i] = f
			i++
		}
		sort.Slice(o.File, func(i, j int) bool { return o.File[i] < o.File[j] })
		o.InlTree = make([]goobj.InlTreeNode, len(pc.InlTree.nodes))
		for i, inl := range pc.InlTree.nodes {
			f, l := ctxt.getFileIndexAndLine(inl.Pos)
			o.InlTree[i] = goobj.InlTreeNode{
				Parent:   int32(inl.Parent),
				File:     goobj.CUFileIndex(f),
				Line:     l,
				Func:     makeSymRef(inl.Func),
				ParentPC: inl.ParentPC,
			}
		}

		o.Write(&b)
		p := b.Bytes()
		isym := &LSym{
			Type:   objabi.SDATA, // for now, I don't think it matters
			PkgIdx: goobj.PkgIdxSelf,
			SymIdx: symidx,
			P:      append([]byte(nil), p...),
			Size:   int64(len(p)),
		}
		isym.Set(AttrIndexed, true)
		symidx++
		infosyms = append(infosyms, isym)
		fn.FuncInfoSym = isym
		b.Reset()

		auxsyms := []*LSym{fn.dwarfRangesSym, fn.dwarfLocSym, fn.dwarfDebugLinesSym, fn.dwarfInfoSym}
		if wi := fn.WasmImport; wi != nil {
			auxsyms = append(auxsyms, wi.AuxSym)
		}
		if we := fn.WasmExport; we != nil {
			auxsyms = append(auxsyms, we.AuxSym)
		}
		for _, s := range auxsyms {
			if s == nil || s.Size == 0 {
				continue
			}
			if s.OnList() {
				panic("a symbol is added to defs multiple times")
			}
			s.PkgIdx = goobj.PkgIdxSelf
			s.SymIdx = symidx
			s.Set(AttrIndexed, true)
			s.Set(AttrOnList, true)
			symidx++
			infosyms = append(infosyms, s)
		}
	}
	ctxt.defs = append(ctxt.defs, infosyms...)
}

func writeAuxSymDebug(ctxt *Link, par *LSym, aux *LSym) {
	// Most aux symbols (ex: funcdata) are not interesting--
	// pick out just the DWARF ones for now.
	switch aux.Type {
	case objabi.SDWARFLOC,
		objabi.SDWARFFCN,
		objabi.SDWARFABSFCN,
		objabi.SDWARFLINES,
		objabi.SDWARFRANGE,
		objabi.SDWARFVAR:
	default:
		return
	}
	ctxt.writeSymDebugNamed(aux, "aux for "+par.Name)
}

func debugAsmEmit(ctxt *Link) {
	if ctxt.Debugasm > 0 {
		ctxt.traverseSyms(traverseDefs, ctxt.writeSymDebug)
		if ctxt.Debugasm > 1 {
			fn := func(par *LSym, aux *LSym) {
				writeAuxSymDebug(ctxt, par, aux)
			}
			ctxt.traverseAuxSyms(traverseAux, fn)
		}
	}
}

func (ctxt *Link) writeSymDebug(s *LSym) {
	ctxt.writeSymDebugNamed(s, s.Name)
}

func (ctxt *Link) writeSymDebugNamed(s *LSym, name string) {
	ver := ""
	if ctxt.Debugasm > 1 {
		ver = fmt.Sprintf("<%d>", s.ABI())
		if ctxt.Debugasm > 2 {
			ver += fmt.Sprintf("<idx %d %d>", s.PkgIdx, s.SymIdx)
		}
	}
	fmt.Fprintf(ctxt.Bso, "%s%s ", name, ver)
	if s.Type != 0 {
		fmt.Fprintf(ctxt.Bso, "%v ", s.Type)
	}
	if s.Static() {
		fmt.Fprint(ctxt.Bso, "static ")
	}
	if s.DuplicateOK() {
		fmt.Fprintf(ctxt.Bso, "dupok ")
	}
	if s.CFunc() {
		fmt.Fprintf(ctxt.Bso, "cfunc ")
	}
	if s.NoSplit() {
		fmt.Fprintf(ctxt.Bso, "nosplit ")
	}
	if s.Func() != nil && s.Func().FuncFlag&abi.FuncFlagTopFrame != 0 {
		fmt.Fprintf(ctxt.Bso, "topframe ")
	}
	if s.Func() != nil && s.Func().FuncFlag&abi.FuncFlagAsm != 0 {
		fmt.Fprintf(ctxt.Bso, "asm ")
	}
	fmt.Fprintf(ctxt.Bso, "size=%d", s.Size)
	if s.Type.IsText() {
		fn := s.Func()
		fmt.Fprintf(ctxt.Bso, " args=%#x locals=%#x funcid=%#x align=%#x", uint64(fn.Args), uint64(fn.Locals), uint64(fn.FuncID), uint64(fn.Align))
		if s.Leaf() {
			fmt.Fprintf(ctxt.Bso, " leaf")
		}
	}
	fmt.Fprintf(ctxt.Bso, "\n")
	if s.Type.IsText() {
		for p := s.Func().Text; p != nil; p = p.Link {
			fmt.Fprintf(ctxt.Bso, "\t%#04x ", uint(int(p.Pc)))
			if ctxt.Debugasm > 1 {
				io.WriteString(ctxt.Bso, p.String())
			} else {
				p.InnermostString(ctxt.Bso)
			}
			fmt.Fprintln(ctxt.Bso)
		}
	}
	for i := 0; i < len(s.P); i += 16 {
		fmt.Fprintf(ctxt.Bso, "\t%#04x", uint(i))
		j := i
		for ; j < i+16 && j < len(s.P); j++ {
			fmt.Fprintf(ctxt.Bso, " %02x", s.P[j])
		}
		for ; j < i+16; j++ {
			fmt.Fprintf(ctxt.Bso, "   ")
		}
		fmt.Fprintf(ctxt.Bso, "  ")
		for j = i; j < i+16 && j < len(s.P); j++ {
			c := int(s.P[j])
			b := byte('.')
			if ' ' <= c && c <= 0x7e {
				b = byte(c)
			}
			ctxt.Bso.WriteByte(b)
		}

		fmt.Fprintf(ctxt.Bso, "\n")
	}

	slices.SortFunc(s.R, relocByOffCmp) // generate stable output
	for _, r := range s.R {
		name := ""
		ver := ""
		if r.Sym != nil {
			name = r.Sym.Name
			if ctxt.Debugasm > 1 {
				ver = fmt.Sprintf("<%d>", r.Sym.ABI())
			}
		} else if r.Type == objabi.R_TLS_LE {
			name = "TLS"
		}
		if ctxt.Arch.InFamily(sys.ARM, sys.PPC64) {
			fmt.Fprintf(ctxt.Bso, "\trel %d+%d t=%v %s%s+%x\n", int(r.Off), r.Siz, r.Type, name, ver, uint64(r.Add))
		} else {
			fmt.Fprintf(ctxt.Bso, "\trel %d+%d t=%v %s%s+%d\n", int(r.Off), r.Siz, r.Type, name, ver, r.Add)
		}
	}
}

// relocByOffCmp compare relocations by their offsets.
func relocByOffCmp(x, y Reloc) int {
	return cmp.Compare(x.Off, y.Off)
}
```