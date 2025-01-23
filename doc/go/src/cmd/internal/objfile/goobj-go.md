Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding: The Goal**

The request asks for the functionality of the Go code, its purpose in the broader Go ecosystem, illustrative examples, and potential pitfalls. The path `go/src/cmd/internal/objfile/goobj.go` immediately suggests this code is related to handling Go object files, likely as part of the compilation or linking process.

**2. High-Level Structure and Key Types:**

I started by scanning the code for top-level declarations: `package objfile`, `import` statements, and the primary struct `goobjFile`. The imports give clues about dependencies:

* `cmd/internal/archive`:  Suggests interaction with archive files, likely `.a` files (Go archives).
* `cmd/internal/goobj`: This is a strong indicator that this package *directly* deals with the internal structure of Go object files (`.o` files).
* `cmd/internal/objabi`:  This is related to object file ABI (Application Binary Interface), things like symbol kinds and relocation types.
* `cmd/internal/sys`:  System architecture information.
* `debug/dwarf`, `debug/gosym`:  Debugging information formats.
* Standard library packages: `errors`, `fmt`, `io`, `os`.

The `goobjFile` struct seems to be the central representation of a parsed Go object file. It holds:

* `goobj *archive.GoObj`: Metadata from the archive structure.
* `r *goobj.Reader`:  A reader specifically for the Go object file format.
* `f *os.File`: The underlying file handle.
* `arch *sys.Arch`: The target architecture.

**3. Deeper Dive into Functions:**

Next, I examined the key functions and their roles:

* **`openGoFile(f *os.File) (*File, error)`:**  This function clearly handles opening and parsing a file. It appears to handle both individual `.o` files and archive files (`.a`). The logic for iterating through archive entries and handling different entry types (`EntryPkgDef`, `EntryGoObj`, `EntryNativeObj`) is crucial. The `openers` variable (not shown in the snippet but referenced) suggests a pluggable mechanism for handling different native object file formats.

* **`goobjName(name string, ver int) string`:** A simple helper for formatting symbol names with versioning information.

* **`goobjReloc` struct and its `String()` method:**  Represents a relocation entry and provides a human-readable string representation. Relocations are essential for linking, as they specify how references between code and data should be resolved.

* **`(*goobjFile) symbols() ([]Sym, error)`:**  This is a core function responsible for extracting symbol information from the Go object file. It handles:
    * Reading referenced symbol names (`RefName`).
    * Resolving symbol references (`resolveSymRef`).
    * Processing defined symbols (`r.Sym(i)`).
    * Handling relocations (`r.Relocs(i)`).
    * Differentiating symbol types (text, data, bss).

* **`(*goobjFile) pcln()`:** This function seems intentionally not implemented for `goobjFile`, suggesting that line number information is handled differently. The comment confirms this and points to `PCToLine`.

* **`(*goobjFile) PCToLine(pc uint64) (string, int, *gosym.Func)`:** This is the primary function for mapping program counter (PC) values to source file names and line numbers. It uses auxiliary symbols (`AuxPcfile`, `AuxPcline`) within the object file to achieve this. The `pcValue` and `step` helper functions are responsible for decoding the variable-length encoding used for PC-to-line tables.

* **`pcValue`, `step`, `readvarint`:** These are low-level helper functions for decoding the compressed data structures used for line number information. The variable-length encoding (`varint`) is a common technique for saving space.

* **`(*goobjFile) text() (textStart uint64, text []byte, err error)`:**  Extracts the entire content of the Go object file as the "text" section. This might seem counterintuitive, but for some tools, treating the whole object as a sequence of bytes is sufficient.

* **`(*goobjFile) goarch() string`:** Returns the target architecture.

* **`(*goobjFile) loadAddress() (uint64, error)`:** Indicates that the load address is not available directly from the Go object file itself.

* **`(*goobjFile) dwarf() (*dwarf.Data, error)`:**  Confirms that DWARF debugging information is not directly embedded in the Go object file format (it might be in a separate section in native object files).

**4. Inferring the Go Language Feature:**

Based on the analysis, it's clear this code is fundamental to the Go build process. It's responsible for *understanding the format of compiled Go code before it's linked into an executable*. This strongly points to the **Go compiler and linker**. The `goobj` package represents the *intermediate representation* of compiled Go code.

**5. Illustrative Examples and Reasoning:**

To provide examples, I focused on the core functionalities:

* **Opening a Go object file:** A simple example demonstrating how `openGoFile` is used.
* **Accessing symbols:** An example showing how to iterate through symbols and their properties. This requires understanding that `symbols()` returns a slice of `Sym` structs.
* **PC-to-line mapping:**  A more complex example demonstrating how `PCToLine` is used to find the source location of an instruction given its address. This requires an understanding of how debug information is structured.

For the reasoning behind these examples, I connected the code's functionality to real-world scenarios: analyzing compiled code, debugging, and symbol resolution.

**6. Identifying Potential Pitfalls:**

I considered common mistakes users might make:

* **Incorrect file type:** Trying to open a non-Go object file.
* **Assuming DWARF is present:**  The code explicitly states it's not.
* **Misinterpreting symbol information:** Understanding the different symbol types and their meaning.

**7. Review and Refinement:**

Finally, I reviewed my analysis to ensure clarity, accuracy, and completeness. I checked if I addressed all aspects of the original request. I also considered the audience and tried to explain concepts in a way that would be understandable to someone familiar with Go but perhaps not the internals of the compiler.

This iterative process of examining the code, understanding its purpose, connecting it to broader concepts, and generating examples is key to effectively analyzing and explaining software.
这段代码是 Go 语言的编译器工具链 `cmd/compile` 的一部分，具体来说，它位于 `cmd/internal/objfile` 包中，并且专注于处理 Go 语言的**中间目标文件（object files），通常以 `.o` 结尾**。 它的主要功能是**解析和读取 Go 语言编译产生的 `.o` 文件中的信息**。

以下是该代码片段的主要功能点：

**1. 打开和解析 Go 对象文件:**

* `openGoFile(f *os.File) (*File, error)`:  这个函数是入口点，用于打开一个 `os.File` 并尝试将其解析为 Go 对象文件。
    * 它首先使用 `archive.Parse` 函数来解析文件，这表明 Go 对象文件实际上是被包装在一种特殊的归档格式中。
    * 它遍历归档文件中的条目 (`a.Entries`)，寻找类型为 `archive.EntryGoObj` 的条目，这代表一个 Go 编译产生的对象文件。
    * 对于 Go 对象文件条目，它读取文件内容，并使用 `goobj.NewReaderFromBytes` 创建一个 `goobj.Reader`，用于读取 Go 对象文件的内部结构。
    * 它还会根据对象文件头部的架构信息 (`e.Obj.Arch`) 查找对应的系统架构信息 (`sys.Arch`).
    * 对于其他类型的条目，比如 `archive.EntryNativeObj` (本地目标文件，如 C/C++ 编译产生的 `.o` 文件)，它会尝试使用一系列 "openers" (未在此代码段中显示) 来解析。
    * 最终，它返回一个 `*File` 结构体，其中包含了对原始文件和解析出的条目的引用。

**2. 构建符号表:**

* `(*goobjFile) symbols() ([]Sym, error)`:  这个方法从 Go 对象文件中提取符号信息。
    * 它使用 `goobj.Reader` 来读取符号表、重定位信息等。
    * 它处理不同类型的符号引用 (例如，包内引用、外部包引用、内置函数等)。
    * 它将 Go 对象文件中的符号信息转换为 `Sym` 结构体的切片，包含了符号的名称、地址、大小、代码类型 (如 'T' 表示 TEXT, 'D' 表示 DATA) 和重定位信息。
    * `resolveSymRef` 函数用于根据 `goobj.SymRef` 解析出符号的完整名称（包括可能的版本信息）。
    * 它区分已定义的符号和引用的符号。
    * 它将重定位信息 (`Relocs`) 也提取出来，并转换为 `Reloc` 结构体。`goobjReloc` 辅助结构体用于格式化重定位信息的字符串表示。

**3. 获取 PC 到行号的映射 (PCLN):**

* `(*goobjFile) pcln() (textStart uint64, symtab, pclntab []byte, err error)`:  这个方法在 `goobjFile` 的实现中直接返回错误，并附带注释 "Should never be called. We implement Liner below, callers should use that instead." 这表明该方法本身并没有实现 PCLN 的获取，而是委托给了 `PCToLine` 方法。
* `(*goobjFile) PCToLine(pc uint64) (string, int, *gosym.Func)`: 这个方法实现了根据程序计数器 (PC) 查找对应的文件名、行号和函数信息。
    * 它依赖于 Go 对象文件中存储的辅助符号 (Auxiliary Symbols)，特别是 `goobj.AuxPcfile` 和 `goobj.AuxPcline`，它们分别指向存储文件名索引表和 PC-Line Number 表的数据。
    * `pcValue` 函数用于在 PC-Line Number 表中查找给定 PC 对应的行号。
    * `step` 和 `readvarint` 是辅助函数，用于解码 PC-Line Number 表中使用的变长编码。

**4. 获取代码段 (Text Section):**

* `(*goobjFile) text() (textStart uint64, text []byte, err error)`:  这个方法将整个 Go 对象文件的内容视为代码段。这是因为 Go 对象文件并不像传统的 ELF 或 Mach-O 文件那样有明确的节 (section) 划分。

**5. 其他辅助方法:**

* `goobjName(name string, ver int) string`:  用于生成带有版本号的符号名称。
* `(*goobjFile) goarch() string`:  返回目标架构的名称。
* `(*goobjFile) loadAddress() (uint64, error)`: 返回错误，表明 Go 对象文件本身不包含加载地址信息。
* `(*goobjFile) dwarf() (*dwarf.Data, error)`: 返回错误，表明 Go 对象文件本身不包含 DWARF 调试信息。 DWARF 信息通常存在于独立的 `.dwarf` 或 `.debug_info` 节中，或者在链接后的可执行文件中。

**推理它是什么 Go 语言功能的实现:**

根据代码的功能和所在的包路径，可以推断出 `goobj.go` 文件是 **Go 语言编译器工具链中用于处理编译产生的中间产物——Go 对象文件**的核心部分。 它服务于以下 Go 语言功能：

* **链接器 (`cmd/link`):** 链接器需要读取 Go 对象文件来合并不同的编译单元，解析符号引用，并生成最终的可执行文件或库。`symbols()` 方法提供的符号信息和重定位信息是链接器进行链接的关键输入。
* **调试器 (`debug/gosym`, `debug/dwarf`):** 虽然 `goobjFile` 本身不直接包含 DWARF 信息，但 `PCToLine` 方法的功能是为调试器提供基本的 PC 到源代码位置的映射能力，这对于程序调试至关重要。
* **其他分析工具:**  任何需要理解 Go 编译输出结构的工具，比如用于代码分析、性能分析等的工具，都可能依赖于 `objfile` 包来解析 Go 对象文件。

**Go 代码举例说明:**

假设我们有一个简单的 Go 源文件 `main.go`:

```go
package main

import "fmt"

func add(a, b int) int {
	return a + b
}

func main() {
	result := add(5, 3)
	fmt.Println(result)
}
```

编译该文件会生成一个 Go 对象文件 (假设架构是 amd64):

```bash
go tool compile -o main.o main.go
```

现在，我们可以使用 `objfile` 包 (虽然它通常在 `go tool` 内部使用，但我们可以模拟其行为) 来读取 `main.o` 中的信息。  为了演示，我们需要创建一个简化的版本，因为它不是一个公开的 API。

```go
package main

import (
	"fmt"
	"os"
	"cmd/internal/objfile" // 注意：这是内部包，正常情况下不应直接使用
)

func main() {
	f, err := os.Open("main.o")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	objFile, err := objfile.Open(f)
	if err != nil {
		fmt.Println("Error opening as objfile:", err)
		return
	}

	for _, entry := range objFile.Entries {
		fmt.Printf("Entry Name: %s\n", entry.Name)
		if goObjFile, ok := entry.Raw.(*objfile.GoObjFile); ok {
			symbols, err := goObjFile.Symbols()
			if err != nil {
				fmt.Println("Error getting symbols:", err)
				continue
			}
			fmt.Println("Symbols:")
			for _, sym := range symbols {
				fmt.Printf("  Name: %s, Addr: %X, Size: %d, Code: %c\n", sym.Name, sym.Addr, sym.Size, sym.Code)
			}

			// 假设我们知道 main 函数的某个地址 (实际中需要更复杂的方法获取)
			mainPC := uint64(0x...) // 替换为实际地址
			file, line, fn := goObjFile.PCToLine(mainPC)
			fmt.Printf("PC %X is in %s:%d, function: %v\n", mainPC, file, line, fn)
		}
	}
}

// 为了演示，需要定义 Open 函数和 GoObjFile 类型 (简化版)
type File struct {
	F       *os.File
	Entries []*Entry
}

type Entry struct {
	Name string
	Raw  interface{}
}

type GoObjFile struct {
	// ... 包含 goobj.Reader 等需要的字段
}

func Open(f *os.File) (*File, error) {
	// ... 简化的 Open 实现，模拟 objfile.openGoFile 的部分功能
	return nil, nil
}

func (f *GoObjFile) Symbols() ([]objfile.Sym, error) {
	// ... 简化的 Symbols 实现
	return nil, nil
}

func (f *GoObjFile) PCToLine(pc uint64) (string, int, *objfile.Func) {
	// ... 简化的 PCToLine 实现
	return "", 0, nil
}
```

**假设的输入与输出:**

**输入 (main.o 文件内容):**

`main.o` 文件是 `main.go` 编译后的二进制数据，包含了符号表、代码、数据、重定位信息等。其具体内容是二进制格式，难以直接展示。

**输出 (上述示例代码运行的简化输出):**

```
Entry Name: main.o
Symbols:
  Name: main.main, Addr: ..., Size: ..., Code: T
  Name: main.add, Addr: ..., Size: ..., Code: T
  Name: fmt.Println, Addr: ..., Size: ..., Code: U
  ... (其他符号)
PC ... is in main.go:10, function: &{Sym:0x...}
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。 它的使用者，如 `go tool compile` 和 `go tool link`，会负责处理命令行参数，并根据参数调用 `objfile` 包的功能来解析对象文件。

**使用者易犯错的点:**

由于 `cmd/internal/objfile` 是一个内部包，普通 Go 开发者通常不会直接使用它。  然而，如果有人尝试直接使用，可能会遇到以下问题：

1. **依赖内部 API:**  内部 API 可能会在 Go 版本更新时发生变化，导致代码失效。
2. **对对象文件格式的理解:**  直接操作对象文件需要深入理解其内部结构，这对于普通开发者来说过于复杂。
3. **缺少必要的上下文:**  `objfile` 包的功能通常需要在 `go tool compile` 或 `go tool link` 的上下文中才能正确使用，例如需要知道当前的构建目标架构等信息。

**总结:**

`go/src/cmd/internal/objfile/goobj.go` 是 Go 语言工具链中负责解析和读取 Go 对象文件的关键组件。它为链接器、调试器和其他分析工具提供了必要的信息，使得这些工具能够理解和处理编译后的 Go 代码。 普通 Go 开发者不需要直接使用这个包，而是通过 `go build`, `go run`, `go test` 等命令间接地使用其功能。

### 提示词
```
这是路径为go/src/cmd/internal/objfile/goobj.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// Parsing of Go intermediate object files and archives.

package objfile

import (
	"cmd/internal/archive"
	"cmd/internal/goobj"
	"cmd/internal/objabi"
	"cmd/internal/sys"
	"debug/dwarf"
	"debug/gosym"
	"errors"
	"fmt"
	"io"
	"os"
)

type goobjFile struct {
	goobj *archive.GoObj
	r     *goobj.Reader
	f     *os.File
	arch  *sys.Arch
}

func openGoFile(f *os.File) (*File, error) {
	a, err := archive.Parse(f, false)
	if err != nil {
		return nil, err
	}
	entries := make([]*Entry, 0, len(a.Entries))
L:
	for _, e := range a.Entries {
		switch e.Type {
		case archive.EntryPkgDef, archive.EntrySentinelNonObj:
			continue
		case archive.EntryGoObj:
			o := e.Obj
			b := make([]byte, o.Size)
			_, err := f.ReadAt(b, o.Offset)
			if err != nil {
				return nil, err
			}
			r := goobj.NewReaderFromBytes(b, false)
			var arch *sys.Arch
			for _, a := range sys.Archs {
				if a.Name == e.Obj.Arch {
					arch = a
					break
				}
			}
			entries = append(entries, &Entry{
				name: e.Name,
				raw:  &goobjFile{e.Obj, r, f, arch},
			})
			continue
		case archive.EntryNativeObj:
			nr := io.NewSectionReader(f, e.Offset, e.Size)
			for _, try := range openers {
				if raw, err := try(nr); err == nil {
					entries = append(entries, &Entry{
						name: e.Name,
						raw:  raw,
					})
					continue L
				}
			}
		}
		return nil, fmt.Errorf("open %s: unrecognized archive member %s", f.Name(), e.Name)
	}
	return &File{f, entries}, nil
}

func goobjName(name string, ver int) string {
	if ver == 0 {
		return name
	}
	return fmt.Sprintf("%s<%d>", name, ver)
}

type goobjReloc struct {
	Off  int32
	Size uint8
	Type objabi.RelocType
	Add  int64
	Sym  string
}

func (r goobjReloc) String(insnOffset uint64) string {
	delta := int64(r.Off) - int64(insnOffset)
	s := fmt.Sprintf("[%d:%d]%s", delta, delta+int64(r.Size), r.Type)
	if r.Sym != "" {
		if r.Add != 0 {
			return fmt.Sprintf("%s:%s+%d", s, r.Sym, r.Add)
		}
		return fmt.Sprintf("%s:%s", s, r.Sym)
	}
	if r.Add != 0 {
		return fmt.Sprintf("%s:%d", s, r.Add)
	}
	return s
}

func (f *goobjFile) symbols() ([]Sym, error) {
	r := f.r
	var syms []Sym

	// Name of referenced indexed symbols.
	nrefName := r.NRefName()
	refNames := make(map[goobj.SymRef]string, nrefName)
	for i := 0; i < nrefName; i++ {
		rn := r.RefName(i)
		refNames[rn.Sym()] = rn.Name(r)
	}

	abiToVer := func(abi uint16) int {
		var ver int
		if abi == goobj.SymABIstatic {
			// Static symbol
			ver = 1
		}
		return ver
	}

	resolveSymRef := func(s goobj.SymRef) string {
		var i uint32
		switch p := s.PkgIdx; p {
		case goobj.PkgIdxInvalid:
			if s.SymIdx != 0 {
				panic("bad sym ref")
			}
			return ""
		case goobj.PkgIdxHashed64:
			i = s.SymIdx + uint32(r.NSym())
		case goobj.PkgIdxHashed:
			i = s.SymIdx + uint32(r.NSym()+r.NHashed64def())
		case goobj.PkgIdxNone:
			i = s.SymIdx + uint32(r.NSym()+r.NHashed64def()+r.NHasheddef())
		case goobj.PkgIdxBuiltin:
			name, abi := goobj.BuiltinName(int(s.SymIdx))
			return goobjName(name, abi)
		case goobj.PkgIdxSelf:
			i = s.SymIdx
		default:
			return refNames[s]
		}
		sym := r.Sym(i)
		return goobjName(sym.Name(r), abiToVer(sym.ABI()))
	}

	// Defined symbols
	ndef := uint32(r.NSym() + r.NHashed64def() + r.NHasheddef() + r.NNonpkgdef())
	for i := uint32(0); i < ndef; i++ {
		osym := r.Sym(i)
		if osym.Name(r) == "" {
			continue // not a real symbol
		}
		name := osym.Name(r)
		ver := osym.ABI()
		name = goobjName(name, abiToVer(ver))
		typ := objabi.SymKind(osym.Type())
		var code rune = '?'
		switch typ {
		case objabi.STEXT, objabi.STEXTFIPS:
			code = 'T'
		case objabi.SRODATA, objabi.SRODATAFIPS:
			code = 'R'
		case objabi.SNOPTRDATA, objabi.SNOPTRDATAFIPS,
			objabi.SDATA, objabi.SDATAFIPS:
			code = 'D'
		case objabi.SBSS, objabi.SNOPTRBSS, objabi.STLSBSS:
			code = 'B'
		}
		if ver >= goobj.SymABIstatic {
			code += 'a' - 'A'
		}

		sym := Sym{
			Name: name,
			Addr: uint64(r.DataOff(i)),
			Size: int64(osym.Siz()),
			Code: code,
		}

		relocs := r.Relocs(i)
		sym.Relocs = make([]Reloc, len(relocs))
		for j := range relocs {
			rel := &relocs[j]
			sym.Relocs[j] = Reloc{
				Addr: uint64(r.DataOff(i)) + uint64(rel.Off()),
				Size: uint64(rel.Siz()),
				Stringer: goobjReloc{
					Off:  rel.Off(),
					Size: rel.Siz(),
					Type: objabi.RelocType(rel.Type()),
					Add:  rel.Add(),
					Sym:  resolveSymRef(rel.Sym()),
				},
			}
		}

		syms = append(syms, sym)
	}

	// Referenced symbols
	n := ndef + uint32(r.NNonpkgref())
	for i := ndef; i < n; i++ {
		osym := r.Sym(i)
		sym := Sym{Name: osym.Name(r), Code: 'U'}
		syms = append(syms, sym)
	}
	for i := 0; i < nrefName; i++ {
		rn := r.RefName(i)
		sym := Sym{Name: rn.Name(r), Code: 'U'}
		syms = append(syms, sym)
	}

	return syms, nil
}

func (f *goobjFile) pcln() (textStart uint64, symtab, pclntab []byte, err error) {
	// Should never be called. We implement Liner below, callers
	// should use that instead.
	return 0, nil, nil, fmt.Errorf("pcln not available in go object file")
}

// Find returns the file name, line, and function data for the given pc.
// Returns "",0,nil if unknown.
// This function implements the Liner interface in preference to pcln() above.
func (f *goobjFile) PCToLine(pc uint64) (string, int, *gosym.Func) {
	r := f.r
	if f.arch == nil {
		return "", 0, nil
	}
	getSymData := func(s goobj.SymRef) []byte {
		if s.PkgIdx != goobj.PkgIdxHashed {
			// We don't need the data for non-hashed symbols, yet.
			panic("not supported")
		}
		i := uint32(s.SymIdx + uint32(r.NSym()+r.NHashed64def()))
		return r.BytesAt(r.DataOff(i), r.DataSize(i))
	}

	ndef := uint32(r.NSym() + r.NHashed64def() + r.NHasheddef() + r.NNonpkgdef())
	for i := uint32(0); i < ndef; i++ {
		osym := r.Sym(i)
		addr := uint64(r.DataOff(i))
		if pc < addr || pc >= addr+uint64(osym.Siz()) {
			continue
		}
		var pcfileSym, pclineSym goobj.SymRef
		for _, a := range r.Auxs(i) {
			switch a.Type() {
			case goobj.AuxPcfile:
				pcfileSym = a.Sym()
			case goobj.AuxPcline:
				pclineSym = a.Sym()
			}
		}
		if pcfileSym.IsZero() || pclineSym.IsZero() {
			continue
		}
		pcline := getSymData(pclineSym)
		line := int(pcValue(pcline, pc-addr, f.arch))
		pcfile := getSymData(pcfileSym)
		fileID := pcValue(pcfile, pc-addr, f.arch)
		fileName := r.File(int(fileID))
		// Note: we provide only the name in the Func structure.
		// We could provide more if needed.
		return fileName, line, &gosym.Func{Sym: &gosym.Sym{Name: osym.Name(r)}}
	}
	return "", 0, nil
}

// pcValue looks up the given PC in a pc value table. target is the
// offset of the pc from the entry point.
func pcValue(tab []byte, target uint64, arch *sys.Arch) int32 {
	val := int32(-1)
	var pc uint64
	for step(&tab, &pc, &val, pc == 0, arch) {
		if target < pc {
			return val
		}
	}
	return -1
}

// step advances to the next pc, value pair in the encoded table.
func step(p *[]byte, pc *uint64, val *int32, first bool, arch *sys.Arch) bool {
	uvdelta := readvarint(p)
	if uvdelta == 0 && !first {
		return false
	}
	if uvdelta&1 != 0 {
		uvdelta = ^(uvdelta >> 1)
	} else {
		uvdelta >>= 1
	}
	vdelta := int32(uvdelta)
	pcdelta := readvarint(p) * uint32(arch.MinLC)
	*pc += uint64(pcdelta)
	*val += vdelta
	return true
}

// readvarint reads, removes, and returns a varint from *p.
func readvarint(p *[]byte) uint32 {
	var v, shift uint32
	s := *p
	for shift = 0; ; shift += 7 {
		b := s[0]
		s = s[1:]
		v |= (uint32(b) & 0x7F) << shift
		if b&0x80 == 0 {
			break
		}
	}
	*p = s
	return v
}

// We treat the whole object file as the text section.
func (f *goobjFile) text() (textStart uint64, text []byte, err error) {
	text = make([]byte, f.goobj.Size)
	_, err = f.f.ReadAt(text, int64(f.goobj.Offset))
	return
}

func (f *goobjFile) goarch() string {
	return f.goobj.Arch
}

func (f *goobjFile) loadAddress() (uint64, error) {
	return 0, fmt.Errorf("unknown load address")
}

func (f *goobjFile) dwarf() (*dwarf.Data, error) {
	return nil, errors.New("no DWARF data in go object file")
}
```