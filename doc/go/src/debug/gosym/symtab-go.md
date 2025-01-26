Response:
Let's break down the thought process for answering the request.

1. **Understand the Goal:** The request asks for a functional summary, identification of the Go feature it relates to, code examples, handling of command-line arguments (if any), and common pitfalls. The context is a specific Go source file, `go/src/debug/gosym/symtab.go`.

2. **Initial Reading and Keyword Spotting:** I scanned the code for prominent structures, types, and function names. Keywords like `Sym`, `Func`, `Table`, `LineTable`, `PCToLine`, `LineToPC`, `LookupSym`, `NewTable`, and comments like "Go symbol and line number tables" immediately stood out. The package name `gosym` also strongly suggests interaction with Go's debugging symbols.

3. **High-Level Functionality Identification:** Based on the keywords, I inferred the core purpose: this code is responsible for parsing and representing the symbol table embedded within Go binaries. This table contains information about functions, their locations in memory (program counters), and their corresponding source code lines.

4. **Deconstructing Key Structures:** I focused on the main data structures:
    * `Sym`: Represents a single symbol (function, variable, etc.). I noted its fields: `Value` (address), `Type`, `Name`, `GoType`, and `Func`. The methods `Static`, `PackageName`, `ReceiverName`, and `BaseName` indicate ways to extract information from the symbol name.
    * `Func`: Represents a function. Key fields are `Entry` (starting address), `Sym` (the associated symbol), `End` (ending address), `Params`, `Locals`, `FrameSize`, `LineTable`, and `Obj`.
    * `Obj`:  Represents a collection of functions, often corresponding to a compilation unit (though this has changed across Go versions). It holds a list of `Funcs` and potentially `Paths` (for older Go versions).
    * `Table`: The central structure, holding lists of `Syms`, `Funcs`, a map of `Files` to `Obj`s (for Go 1.2+), and `Objs`. The `go12line` field suggests special handling for Go 1.2 symbol tables.

5. **Analyzing Core Functions:** I examined the main functions to understand their roles:
    * `NewTable`: This function is clearly responsible for parsing the raw byte slice of the symbol table (`symtab`) and the line number table (`pcln`) to create the `Table` object. The `walksymtab` helper function is used to iterate through the symbol table data.
    * `PCToFunc`:  Finds the function containing a given program counter.
    * `PCToLine`: Finds the source file and line number corresponding to a program counter.
    * `LineToPC`: Finds the program counter for a given file and line number.
    * `LookupSym`: Finds a symbol by its name.
    * `LookupFunc`: Finds a function by its name.
    * `SymByAddr`: Finds a symbol by its memory address.

6. **Connecting to Go Features:** Based on the identified functionality, it's clear this code is a fundamental part of Go's reflection and debugging capabilities. Features like stack trace printing, runtime error reporting (panic messages), and tools like `go tool pprof` rely on this information.

7. **Developing Code Examples:**  I aimed for concise examples demonstrating the core functionalities. `PCToLine` and `LineToPC` are natural candidates. I needed to simulate having a `Table` object, which requires reading symbol table data. Since the prompt didn't provide a readily available binary, I focused on the *usage* of the functions *assuming* a `Table` is available. I included comments explaining the purpose of each step. For `LineToPC`, I anticipated potential errors like `UnknownFileError` and `UnknownLineError`.

8. **Considering Command-Line Arguments:**  I reviewed the code for any direct handling of `os.Args` or similar. The `gosym` package itself doesn't directly process command-line arguments in this code. However, tools *using* `gosym` (like `go tool pprof`) would, so I highlighted this indirect relationship.

9. **Identifying Potential Pitfalls:** I thought about common mistakes users might make when interacting with this kind of information:
    * **Incorrect Binary:**  Using symbol table data from a different binary than the one being debugged.
    * **Stripped Binaries:**  Attempting to use symbol tables from stripped binaries (which lack symbol information).
    * **Go Version Compatibility:** Subtle differences in symbol table formats across Go versions.

10. **Structuring the Answer:** I organized the information logically using the categories requested: 功能, 功能的实现, 代码举例, 命令行参数, 易犯错的点. I used clear and concise Chinese.

11. **Refinement and Review:** I reread the generated answer, ensuring accuracy, clarity, and completeness, referring back to the code snippet as needed. For example, I made sure the explanations of `Obj`'s evolution across Go versions matched the comments in the code. I also double-checked the error types returned by `LineToPC`.

This iterative process of reading, analyzing, connecting to broader concepts, and constructing examples helped in generating a comprehensive and accurate response. The focus was on extracting the essential purpose and usage patterns of the provided code snippet within the larger Go ecosystem.
这段代码是 Go 语言标准库 `debug/gosym` 包中 `symtab.go` 文件的一部分。它主要负责解析 Go 编译器生成的二进制文件中的符号表 (symbol table)。符号表包含了程序中各种符号的信息，例如函数名、变量名、它们的地址以及类型信息等。

**功能列举:**

1. **解析符号表数据:**  `NewTable` 函数是核心，它接收包含符号表数据的字节切片 (`symtab`) 和行号表 (`pcln`)，并将其解析成内存中的 `Table` 结构。
2. **存储符号信息:** 定义了 `Sym` 结构体来表示单个符号表条目，包含符号的值 (地址 `Value`)、类型 (`Type`)、名称 (`Name`)、Go 类型 (`GoType`) 以及指向关联的 `Func` 结构体的指针。
3. **存储函数信息:** 定义了 `Func` 结构体来表示一个函数，包含函数的入口地址 (`Entry`)、关联的 `Sym` 信息、结束地址 (`End`)、参数 (`Params`)、局部变量 (`Locals`)、帧大小 (`FrameSize`) 和行号表 (`LineTable`)。
4. **存储对象文件信息:** 定义了 `Obj` 结构体来表示符号表中的一组函数，对应于编译过程中的一个目标文件。
5. **按程序计数器查找函数:** `PCToFunc` 函数接收一个程序计数器 (PC) 值，然后在符号表中查找包含该 PC 值的函数，并返回对应的 `Func` 结构体。
6. **按程序计数器查找行号信息:** `PCToLine` 函数接收一个程序计数器值，然后在符号表中查找该 PC 对应的源文件名和行号。
7. **按文件名和行号查找程序计数器:** `LineToPC` 函数接收文件名和行号，然后在符号表中查找该行代码对应的程序计数器。
8. **按名称查找符号:** `LookupSym` 函数接收符号名称，然后在符号表中查找具有该名称的符号，并返回对应的 `Sym` 结构体。
9. **按名称查找函数:** `LookupFunc` 函数接收函数名称，然后在符号表中查找具有该名称的函数，并返回对应的 `Func` 结构体。
10. **按地址查找符号:** `SymByAddr` 函数接收一个地址，然后在符号表中查找起始地址为该地址的符号，并返回对应的 `Sym` 结构体。
11. **处理不同 Go 版本的符号表格式:** 代码中通过检查 magic number (`littleEndianSymtab`, `bigEndianSymtab`, `oldLittleEndianSymtab`) 和版本信息来兼容不同 Go 版本的符号表格式。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 **反射 (Reflection)** 和 **调试 (Debugging)** 功能的底层实现。它提供了从二进制代码到源代码映射的关键信息，使得 Go 语言能够：

* **打印堆栈跟踪 (Stack Trace):**  当程序发生 panic 或使用 `runtime/debug` 包时，`PCToFunc` 和 `PCToLine` 可以将程序计数器转换为函数名和源代码位置，生成易于理解的错误报告。
* **支持调试器 (Debuggers):**  像 `dlv` 这样的 Go 调试器会使用符号表信息来设置断点、单步执行、查看变量值等。
* **性能分析 (Profiling):**  `go tool pprof` 等性能分析工具会利用符号表信息将采样到的程序计数器映射到函数，从而分析程序的性能瓶颈。
* **反射机制中的函数信息:**  `reflect` 包在某些场景下也会用到符号表信息来获取函数的元数据。

**Go 代码举例说明:**

假设我们有一个编译后的 Go 程序 `myprogram`。我们可以使用 `debug/gosym` 包来读取并使用它的符号表信息。

```go
package main

import (
	"debug/gosym"
	"debug/macho" // 或 debug/pe 对于 Windows
	"fmt"
	"log"
	"os"
)

func main() {
	// 假设我们有一个编译好的 Go 程序 "myprogram"

	// 1. 打开可执行文件
	f, err := os.Open("myprogram")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// 2. 解析 Mach-O 或 PE 文件头 (取决于操作系统)
	m, err := macho.NewFile(f) // 或者 pe.NewFile(f)
	if err != nil {
		log.Fatal(err)
	}

	// 3. 获取 .gosymtab 和 .gopclntab section 的数据
	var symtabData []byte
	var pclntabData []byte
	for _, sect := range m.Sections {
		if sect.Name == "__gosymtab" || sect.Name == ".gosymtab" { // 不同平台可能名称不同
			symtabData, err = sect.Data()
			if err != nil {
				log.Fatal(err)
			}
		}
		if sect.Name == "__gopclntab" || sect.Name == ".gopclntab" {
			pclntabData, err = sect.Data()
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	if len(symtabData) == 0 || len(pclntabData) == 0 {
		log.Fatal("符号表或行号表数据为空，可能程序被 strip 了")
	}

	// 4. 创建 LineTable
	pcln := gosym.NewLineTable(pclntabData, m.Section("__text").Addr) // 获取 __text 段的起始地址

	// 5. 创建 Table
	table, err := gosym.NewTable(symtabData, pcln)
	if err != nil {
		log.Fatal(err)
	}

	// 假设我们有一个程序计数器值 (例如，从 panic 信息中获取)
	pc := uint64(0x10a80b0) // 需要替换成实际的 PC 值

	// 6. 使用 Table 的方法查找信息
	file, line, fn := table.PCToLine(pc)
	if fn != nil {
		fmt.Printf("PC 0x%x 在函数 %s, 文件 %s, 行 %d\n", pc, fn.Name, file, line)
	} else {
		fmt.Printf("找不到 PC 0x%x 对应的函数\n", pc)
	}

	// 查找函数 "main.main"
	mainFunc := table.LookupFunc("main.main")
	if mainFunc != nil {
		fmt.Printf("函数 main.main 的入口地址是 0x%x\n", mainFunc.Entry)
	} else {
		fmt.Println("找不到函数 main.main")
	}

	// 查找符号 "main.globalVar" (假设存在一个全局变量)
	globalVar := table.LookupSym("main.globalVar")
	if globalVar != nil {
		fmt.Printf("符号 main.globalVar 的地址是 0x%x\n", globalVar.Value)
	} else {
		fmt.Println("找不到符号 main.globalVar")
	}
}
```

**假设的输入与输出:**

* **输入:**
    * `myprogram` 文件是一个已经编译好的 Go 可执行文件，其中包含符号表和行号表信息。
    * `pc` 的值为 `0x10a80b0`，这个值在 `myprogram` 的某个函数的代码范围内。
* **输出:**

```
PC 0x10a80b0 在函数 main.myFunction, 文件 /path/to/myprogram/main.go, 行 25
函数 main.main 的入口地址是 0x10a8000
找不到符号 main.globalVar
```

**命令行参数的具体处理:**

这段代码本身 **不直接处理命令行参数**。 `debug/gosym` 包是一个底层的库，它专注于解析符号表数据。处理命令行参数通常发生在更高层次的应用中，例如：

* **`go tool pprof`:**  这个工具会接收命令行参数，例如要分析的二进制文件和 profile 数据文件。它会在内部使用 `debug/gosym` 来解析二进制文件的符号表，以便将 profile 数据中的地址映射到函数名。
* **调试器 (`dlv`)**:  调试器会接收要调试的二进制文件作为命令行参数，并利用 `debug/gosym` 来进行调试操作。

**使用者易犯错的点:**

1. **使用被 strip 后的二进制文件:** 如果编译 Go 程序时使用了 `-s` 或 `-w` 标志来去除符号表和调试信息，那么 `NewTable` 函数将无法解析到有效的符号信息，或者返回的 `Table` 对象将包含有限的信息。这会导致 `PCToLine`、`LookupFunc` 等方法返回不正确的结果或 `nil`。
   ```bash
   go build -ldflags="-s -w" myprogram.go  # 生成被 strip 后的二进制文件
   ```

2. **使用与当前二进制文件不匹配的符号表数据:**  如果尝试使用从另一个不同版本的二进制文件或不同编译选项生成的二进制文件中提取的符号表数据来解析当前的二进制文件，会导致解析错误或得到不准确的映射结果。

3. **假设所有 Go 版本的符号表格式都相同:**  虽然 `debug/gosym` 包尝试兼容不同的 Go 版本，但不同版本之间可能存在细微的差异。因此，使用针对特定 Go 版本编译的二进制文件的符号表数据来解析另一个 Go 版本编译的二进制文件，可能会遇到问题。代码中可以看到对不同版本符号表 magic number 的处理。

4. **没有正确处理错误:** 在实际应用中，解析符号表可能会遇到各种错误 (例如文件不存在、数据格式错误等)。使用者需要妥善处理这些错误，避免程序崩溃或产生误导性的结果。

总而言之，`go/src/debug/gosym/symtab.go` 是 Go 语言调试和反射能力的基石，它负责将二进制代码中的符号信息转化为可操作的数据结构，为各种工具和库提供了必要的信息。

Prompt: 
```
这是路径为go/src/debug/gosym/symtab.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gosym implements access to the Go symbol
// and line number tables embedded in Go binaries generated
// by the gc compilers.
package gosym

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

/*
 * Symbols
 */

// A Sym represents a single symbol table entry.
type Sym struct {
	Value  uint64
	Type   byte
	Name   string
	GoType uint64
	// If this symbol is a function symbol, the corresponding Func
	Func *Func

	goVersion version
}

// Static reports whether this symbol is static (not visible outside its file).
func (s *Sym) Static() bool { return s.Type >= 'a' }

// nameWithoutInst returns s.Name if s.Name has no brackets (does not reference an
// instantiated type, function, or method). If s.Name contains brackets, then it
// returns s.Name with all the contents between (and including) the outermost left
// and right bracket removed. This is useful to ignore any extra slashes or dots
// inside the brackets from the string searches below, where needed.
func (s *Sym) nameWithoutInst() string {
	start := strings.Index(s.Name, "[")
	if start < 0 {
		return s.Name
	}
	end := strings.LastIndex(s.Name, "]")
	if end < 0 {
		// Malformed name, should contain closing bracket too.
		return s.Name
	}
	return s.Name[0:start] + s.Name[end+1:]
}

// PackageName returns the package part of the symbol name,
// or the empty string if there is none.
func (s *Sym) PackageName() string {
	name := s.nameWithoutInst()

	// Since go1.20, a prefix of "type:" and "go:" is a compiler-generated symbol,
	// they do not belong to any package.
	//
	// See cmd/compile/internal/base/link.go:ReservedImports variable.
	if s.goVersion >= ver120 && (strings.HasPrefix(name, "go:") || strings.HasPrefix(name, "type:")) {
		return ""
	}

	// For go1.18 and below, the prefix are "type." and "go." instead.
	if s.goVersion <= ver118 && (strings.HasPrefix(name, "go.") || strings.HasPrefix(name, "type.")) {
		return ""
	}

	pathend := strings.LastIndex(name, "/")
	if pathend < 0 {
		pathend = 0
	}

	if i := strings.Index(name[pathend:], "."); i != -1 {
		return name[:pathend+i]
	}
	return ""
}

// ReceiverName returns the receiver type name of this symbol,
// or the empty string if there is none.  A receiver name is only detected in
// the case that s.Name is fully-specified with a package name.
func (s *Sym) ReceiverName() string {
	name := s.nameWithoutInst()
	// If we find a slash in name, it should precede any bracketed expression
	// that was removed, so pathend will apply correctly to name and s.Name.
	pathend := strings.LastIndex(name, "/")
	if pathend < 0 {
		pathend = 0
	}
	// Find the first dot after pathend (or from the beginning, if there was
	// no slash in name).
	l := strings.Index(name[pathend:], ".")
	// Find the last dot after pathend (or the beginning).
	r := strings.LastIndex(name[pathend:], ".")
	if l == -1 || r == -1 || l == r {
		// There is no receiver if we didn't find two distinct dots after pathend.
		return ""
	}
	// Given there is a trailing '.' that is in name, find it now in s.Name.
	// pathend+l should apply to s.Name, because it should be the dot in the
	// package name.
	r = strings.LastIndex(s.Name[pathend:], ".")
	return s.Name[pathend+l+1 : pathend+r]
}

// BaseName returns the symbol name without the package or receiver name.
func (s *Sym) BaseName() string {
	name := s.nameWithoutInst()
	if i := strings.LastIndex(name, "."); i != -1 {
		if s.Name != name {
			brack := strings.Index(s.Name, "[")
			if i > brack {
				// BaseName is a method name after the brackets, so
				// recalculate for s.Name. Otherwise, i applies
				// correctly to s.Name, since it is before the
				// brackets.
				i = strings.LastIndex(s.Name, ".")
			}
		}
		return s.Name[i+1:]
	}
	return s.Name
}

// A Func collects information about a single function.
type Func struct {
	Entry uint64
	*Sym
	End       uint64
	Params    []*Sym // nil for Go 1.3 and later binaries
	Locals    []*Sym // nil for Go 1.3 and later binaries
	FrameSize int
	LineTable *LineTable
	Obj       *Obj
}

// An Obj represents a collection of functions in a symbol table.
//
// The exact method of division of a binary into separate Objs is an internal detail
// of the symbol table format.
//
// In early versions of Go each source file became a different Obj.
//
// In Go 1 and Go 1.1, each package produced one Obj for all Go sources
// and one Obj per C source file.
//
// In Go 1.2, there is a single Obj for the entire program.
type Obj struct {
	// Funcs is a list of functions in the Obj.
	Funcs []Func

	// In Go 1.1 and earlier, Paths is a list of symbols corresponding
	// to the source file names that produced the Obj.
	// In Go 1.2, Paths is nil.
	// Use the keys of Table.Files to obtain a list of source files.
	Paths []Sym // meta
}

/*
 * Symbol tables
 */

// Table represents a Go symbol table. It stores all of the
// symbols decoded from the program and provides methods to translate
// between symbols, names, and addresses.
type Table struct {
	Syms  []Sym // nil for Go 1.3 and later binaries
	Funcs []Func
	Files map[string]*Obj // for Go 1.2 and later all files map to one Obj
	Objs  []Obj           // for Go 1.2 and later only one Obj in slice

	go12line *LineTable // Go 1.2 line number table
}

type sym struct {
	value  uint64
	gotype uint64
	typ    byte
	name   []byte
}

var (
	littleEndianSymtab    = []byte{0xFD, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00}
	bigEndianSymtab       = []byte{0xFF, 0xFF, 0xFF, 0xFD, 0x00, 0x00, 0x00}
	oldLittleEndianSymtab = []byte{0xFE, 0xFF, 0xFF, 0xFF, 0x00, 0x00}
)

func walksymtab(data []byte, fn func(sym) error) error {
	if len(data) == 0 { // missing symtab is okay
		return nil
	}
	var order binary.ByteOrder = binary.BigEndian
	newTable := false
	switch {
	case bytes.HasPrefix(data, oldLittleEndianSymtab):
		// Same as Go 1.0, but little endian.
		// Format was used during interim development between Go 1.0 and Go 1.1.
		// Should not be widespread, but easy to support.
		data = data[6:]
		order = binary.LittleEndian
	case bytes.HasPrefix(data, bigEndianSymtab):
		newTable = true
	case bytes.HasPrefix(data, littleEndianSymtab):
		newTable = true
		order = binary.LittleEndian
	}
	var ptrsz int
	if newTable {
		if len(data) < 8 {
			return &DecodingError{len(data), "unexpected EOF", nil}
		}
		ptrsz = int(data[7])
		if ptrsz != 4 && ptrsz != 8 {
			return &DecodingError{7, "invalid pointer size", ptrsz}
		}
		data = data[8:]
	}
	var s sym
	p := data
	for len(p) >= 4 {
		var typ byte
		if newTable {
			// Symbol type, value, Go type.
			typ = p[0] & 0x3F
			wideValue := p[0]&0x40 != 0
			goType := p[0]&0x80 != 0
			if typ < 26 {
				typ += 'A'
			} else {
				typ += 'a' - 26
			}
			s.typ = typ
			p = p[1:]
			if wideValue {
				if len(p) < ptrsz {
					return &DecodingError{len(data), "unexpected EOF", nil}
				}
				// fixed-width value
				if ptrsz == 8 {
					s.value = order.Uint64(p[0:8])
					p = p[8:]
				} else {
					s.value = uint64(order.Uint32(p[0:4]))
					p = p[4:]
				}
			} else {
				// varint value
				s.value = 0
				shift := uint(0)
				for len(p) > 0 && p[0]&0x80 != 0 {
					s.value |= uint64(p[0]&0x7F) << shift
					shift += 7
					p = p[1:]
				}
				if len(p) == 0 {
					return &DecodingError{len(data), "unexpected EOF", nil}
				}
				s.value |= uint64(p[0]) << shift
				p = p[1:]
			}
			if goType {
				if len(p) < ptrsz {
					return &DecodingError{len(data), "unexpected EOF", nil}
				}
				// fixed-width go type
				if ptrsz == 8 {
					s.gotype = order.Uint64(p[0:8])
					p = p[8:]
				} else {
					s.gotype = uint64(order.Uint32(p[0:4]))
					p = p[4:]
				}
			}
		} else {
			// Value, symbol type.
			s.value = uint64(order.Uint32(p[0:4]))
			if len(p) < 5 {
				return &DecodingError{len(data), "unexpected EOF", nil}
			}
			typ = p[4]
			if typ&0x80 == 0 {
				return &DecodingError{len(data) - len(p) + 4, "bad symbol type", typ}
			}
			typ &^= 0x80
			s.typ = typ
			p = p[5:]
		}

		// Name.
		var i int
		var nnul int
		for i = 0; i < len(p); i++ {
			if p[i] == 0 {
				nnul = 1
				break
			}
		}
		switch typ {
		case 'z', 'Z':
			p = p[i+nnul:]
			for i = 0; i+2 <= len(p); i += 2 {
				if p[i] == 0 && p[i+1] == 0 {
					nnul = 2
					break
				}
			}
		}
		if len(p) < i+nnul {
			return &DecodingError{len(data), "unexpected EOF", nil}
		}
		s.name = p[0:i]
		i += nnul
		p = p[i:]

		if !newTable {
			if len(p) < 4 {
				return &DecodingError{len(data), "unexpected EOF", nil}
			}
			// Go type.
			s.gotype = uint64(order.Uint32(p[:4]))
			p = p[4:]
		}
		fn(s)
	}
	return nil
}

// NewTable decodes the Go symbol table (the ".gosymtab" section in ELF),
// returning an in-memory representation.
// Starting with Go 1.3, the Go symbol table no longer includes symbol data.
func NewTable(symtab []byte, pcln *LineTable) (*Table, error) {
	var n int
	err := walksymtab(symtab, func(s sym) error {
		n++
		return nil
	})
	if err != nil {
		return nil, err
	}

	var t Table
	if pcln.isGo12() {
		t.go12line = pcln
	}
	fname := make(map[uint16]string)
	t.Syms = make([]Sym, 0, n)
	nf := 0
	nz := 0
	lasttyp := uint8(0)
	err = walksymtab(symtab, func(s sym) error {
		n := len(t.Syms)
		t.Syms = t.Syms[0 : n+1]
		ts := &t.Syms[n]
		ts.Type = s.typ
		ts.Value = s.value
		ts.GoType = s.gotype
		ts.goVersion = pcln.version
		switch s.typ {
		default:
			// rewrite name to use . instead of · (c2 b7)
			w := 0
			b := s.name
			for i := 0; i < len(b); i++ {
				if b[i] == 0xc2 && i+1 < len(b) && b[i+1] == 0xb7 {
					i++
					b[i] = '.'
				}
				b[w] = b[i]
				w++
			}
			ts.Name = string(s.name[0:w])
		case 'z', 'Z':
			if lasttyp != 'z' && lasttyp != 'Z' {
				nz++
			}
			for i := 0; i < len(s.name); i += 2 {
				eltIdx := binary.BigEndian.Uint16(s.name[i : i+2])
				elt, ok := fname[eltIdx]
				if !ok {
					return &DecodingError{-1, "bad filename code", eltIdx}
				}
				if n := len(ts.Name); n > 0 && ts.Name[n-1] != '/' {
					ts.Name += "/"
				}
				ts.Name += elt
			}
		}
		switch s.typ {
		case 'T', 't', 'L', 'l':
			nf++
		case 'f':
			fname[uint16(s.value)] = ts.Name
		}
		lasttyp = s.typ
		return nil
	})
	if err != nil {
		return nil, err
	}

	t.Funcs = make([]Func, 0, nf)
	t.Files = make(map[string]*Obj)

	var obj *Obj
	if t.go12line != nil {
		// Put all functions into one Obj.
		t.Objs = make([]Obj, 1)
		obj = &t.Objs[0]
		t.go12line.go12MapFiles(t.Files, obj)
	} else {
		t.Objs = make([]Obj, 0, nz)
	}

	// Count text symbols and attach frame sizes, parameters, and
	// locals to them. Also, find object file boundaries.
	lastf := 0
	for i := 0; i < len(t.Syms); i++ {
		sym := &t.Syms[i]
		switch sym.Type {
		case 'Z', 'z': // path symbol
			if t.go12line != nil {
				// Go 1.2 binaries have the file information elsewhere. Ignore.
				break
			}
			// Finish the current object
			if obj != nil {
				obj.Funcs = t.Funcs[lastf:]
			}
			lastf = len(t.Funcs)

			// Start new object
			n := len(t.Objs)
			t.Objs = t.Objs[0 : n+1]
			obj = &t.Objs[n]

			// Count & copy path symbols
			var end int
			for end = i + 1; end < len(t.Syms); end++ {
				if c := t.Syms[end].Type; c != 'Z' && c != 'z' {
					break
				}
			}
			obj.Paths = t.Syms[i:end]
			i = end - 1 // loop will i++

			// Record file names
			depth := 0
			for j := range obj.Paths {
				s := &obj.Paths[j]
				if s.Name == "" {
					depth--
				} else {
					if depth == 0 {
						t.Files[s.Name] = obj
					}
					depth++
				}
			}

		case 'T', 't', 'L', 'l': // text symbol
			if n := len(t.Funcs); n > 0 {
				t.Funcs[n-1].End = sym.Value
			}
			if sym.Name == "runtime.etext" || sym.Name == "etext" {
				continue
			}

			// Count parameter and local (auto) syms
			var np, na int
			var end int
		countloop:
			for end = i + 1; end < len(t.Syms); end++ {
				switch t.Syms[end].Type {
				case 'T', 't', 'L', 'l', 'Z', 'z':
					break countloop
				case 'p':
					np++
				case 'a':
					na++
				}
			}

			// Fill in the function symbol
			n := len(t.Funcs)
			t.Funcs = t.Funcs[0 : n+1]
			fn := &t.Funcs[n]
			sym.Func = fn
			fn.Params = make([]*Sym, 0, np)
			fn.Locals = make([]*Sym, 0, na)
			fn.Sym = sym
			fn.Entry = sym.Value
			fn.Obj = obj
			if t.go12line != nil {
				// All functions share the same line table.
				// It knows how to narrow down to a specific
				// function quickly.
				fn.LineTable = t.go12line
			} else if pcln != nil {
				fn.LineTable = pcln.slice(fn.Entry)
				pcln = fn.LineTable
			}
			for j := i; j < end; j++ {
				s := &t.Syms[j]
				switch s.Type {
				case 'm':
					fn.FrameSize = int(s.Value)
				case 'p':
					n := len(fn.Params)
					fn.Params = fn.Params[0 : n+1]
					fn.Params[n] = s
				case 'a':
					n := len(fn.Locals)
					fn.Locals = fn.Locals[0 : n+1]
					fn.Locals[n] = s
				}
			}
			i = end - 1 // loop will i++
		}
	}

	if t.go12line != nil && nf == 0 {
		t.Funcs = t.go12line.go12Funcs()
	}
	if obj != nil {
		obj.Funcs = t.Funcs[lastf:]
	}
	return &t, nil
}

// PCToFunc returns the function containing the program counter pc,
// or nil if there is no such function.
func (t *Table) PCToFunc(pc uint64) *Func {
	funcs := t.Funcs
	for len(funcs) > 0 {
		m := len(funcs) / 2
		fn := &funcs[m]
		switch {
		case pc < fn.Entry:
			funcs = funcs[0:m]
		case fn.Entry <= pc && pc < fn.End:
			return fn
		default:
			funcs = funcs[m+1:]
		}
	}
	return nil
}

// PCToLine looks up line number information for a program counter.
// If there is no information, it returns fn == nil.
func (t *Table) PCToLine(pc uint64) (file string, line int, fn *Func) {
	if fn = t.PCToFunc(pc); fn == nil {
		return
	}
	if t.go12line != nil {
		file = t.go12line.go12PCToFile(pc)
		line = t.go12line.go12PCToLine(pc)
	} else {
		file, line = fn.Obj.lineFromAline(fn.LineTable.PCToLine(pc))
	}
	return
}

// LineToPC looks up the first program counter on the given line in
// the named file. It returns [UnknownFileError] or [UnknownLineError] if
// there is an error looking up this line.
func (t *Table) LineToPC(file string, line int) (pc uint64, fn *Func, err error) {
	obj, ok := t.Files[file]
	if !ok {
		return 0, nil, UnknownFileError(file)
	}

	if t.go12line != nil {
		pc := t.go12line.go12LineToPC(file, line)
		if pc == 0 {
			return 0, nil, &UnknownLineError{file, line}
		}
		return pc, t.PCToFunc(pc), nil
	}

	abs, err := obj.alineFromLine(file, line)
	if err != nil {
		return
	}
	for i := range obj.Funcs {
		f := &obj.Funcs[i]
		pc := f.LineTable.LineToPC(abs, f.End)
		if pc != 0 {
			return pc, f, nil
		}
	}
	return 0, nil, &UnknownLineError{file, line}
}

// LookupSym returns the text, data, or bss symbol with the given name,
// or nil if no such symbol is found.
func (t *Table) LookupSym(name string) *Sym {
	// TODO(austin) Maybe make a map
	for i := range t.Syms {
		s := &t.Syms[i]
		switch s.Type {
		case 'T', 't', 'L', 'l', 'D', 'd', 'B', 'b':
			if s.Name == name {
				return s
			}
		}
	}
	return nil
}

// LookupFunc returns the text, data, or bss symbol with the given name,
// or nil if no such symbol is found.
func (t *Table) LookupFunc(name string) *Func {
	for i := range t.Funcs {
		f := &t.Funcs[i]
		if f.Sym.Name == name {
			return f
		}
	}
	return nil
}

// SymByAddr returns the text, data, or bss symbol starting at the given address.
func (t *Table) SymByAddr(addr uint64) *Sym {
	for i := range t.Syms {
		s := &t.Syms[i]
		switch s.Type {
		case 'T', 't', 'L', 'l', 'D', 'd', 'B', 'b':
			if s.Value == addr {
				return s
			}
		}
	}
	return nil
}

/*
 * Object files
 */

// This is legacy code for Go 1.1 and earlier, which used the
// Plan 9 format for pc-line tables. This code was never quite
// correct. It's probably very close, and it's usually correct, but
// we never quite found all the corner cases.
//
// Go 1.2 and later use a simpler format, documented at golang.org/s/go12symtab.

func (o *Obj) lineFromAline(aline int) (string, int) {
	type stackEnt struct {
		path   string
		start  int
		offset int
		prev   *stackEnt
	}

	noPath := &stackEnt{"", 0, 0, nil}
	tos := noPath

pathloop:
	for _, s := range o.Paths {
		val := int(s.Value)
		switch {
		case val > aline:
			break pathloop

		case val == 1:
			// Start a new stack
			tos = &stackEnt{s.Name, val, 0, noPath}

		case s.Name == "":
			// Pop
			if tos == noPath {
				return "<malformed symbol table>", 0
			}
			tos.prev.offset += val - tos.start
			tos = tos.prev

		default:
			// Push
			tos = &stackEnt{s.Name, val, 0, tos}
		}
	}

	if tos == noPath {
		return "", 0
	}
	return tos.path, aline - tos.start - tos.offset + 1
}

func (o *Obj) alineFromLine(path string, line int) (int, error) {
	if line < 1 {
		return 0, &UnknownLineError{path, line}
	}

	for i, s := range o.Paths {
		// Find this path
		if s.Name != path {
			continue
		}

		// Find this line at this stack level
		depth := 0
		var incstart int
		line += int(s.Value)
	pathloop:
		for _, s := range o.Paths[i:] {
			val := int(s.Value)
			switch {
			case depth == 1 && val >= line:
				return line - 1, nil

			case s.Name == "":
				depth--
				if depth == 0 {
					break pathloop
				} else if depth == 1 {
					line += val - incstart
				}

			default:
				if depth == 1 {
					incstart = val
				}
				depth++
			}
		}
		return 0, &UnknownLineError{path, line}
	}
	return 0, UnknownFileError(path)
}

/*
 * Errors
 */

// UnknownFileError represents a failure to find the specific file in
// the symbol table.
type UnknownFileError string

func (e UnknownFileError) Error() string { return "unknown file: " + string(e) }

// UnknownLineError represents a failure to map a line to a program
// counter, either because the line is beyond the bounds of the file
// or because there is no code on the given line.
type UnknownLineError struct {
	File string
	Line int
}

func (e *UnknownLineError) Error() string {
	return "no code at " + e.File + ":" + strconv.Itoa(e.Line)
}

// DecodingError represents an error during the decoding of
// the symbol table.
type DecodingError struct {
	off int
	msg string
	val any
}

func (e *DecodingError) Error() string {
	msg := e.msg
	if e.val != nil {
		msg += fmt.Sprintf(" '%v'", e.val)
	}
	msg += fmt.Sprintf(" at byte %#x", e.off)
	return msg
}

"""



```