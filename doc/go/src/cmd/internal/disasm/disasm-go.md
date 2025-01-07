Response: Let's break down the thought process for analyzing the provided Go code.

**1. Understanding the Core Purpose:**

The first step is to read the package comment and the `Disasm` struct definition. This immediately tells us the package is about disassembling Go binaries. The `Disasm` struct holds the essential information needed for this: symbols, program counter to line number mappings, the executable code itself, architecture, and a disassembler function.

**2. Identifying Key Functions and Their Roles:**

Next, scan the top-level functions:

* `DisasmForFile`:  This looks like the main entry point for creating a `Disasm` instance from a file. It suggests the code operates on compiled Go executables or object files.
* `disasmForEntry`:  A helper for `DisasmForFile`, probably dealing with individual entries within a potentially multi-entry file.
* `lookup`:  This clearly aims to find the symbol name associated with a given memory address. This is crucial for making disassembled output readable.
* `base`:  A utility to extract the filename from a path, likely for display purposes in the disassembled output.
* `CachedFile` and `FileCache`:  These are clearly for caching file contents, probably source code, to enhance performance when displaying source alongside assembly.
* `Print`: This seems to be the function that generates the disassembled output. It takes a writer, a filter, start/end addresses, and flags for printing source code and using GNU assembly syntax.
* `Decode`: This function performs the actual disassembly, iterating through the code and calling the architecture-specific disassembler.

**3. Dissecting `DisasmForFile` and `disasmForEntry`:**

Focus on how the `Disasm` struct is initialized. These functions extract crucial information from the `objfile.File` or `objfile.Entry`: symbols, PC-line mapping, the `.text` section (executable code), and the target architecture. The filtering of symbols like "runtime.text" is also notable – this is a common optimization to exclude internal runtime symbols from disassembly output by default. The code confirms the package relies on `cmd/internal/objfile` to parse the binary file format.

**4. Analyzing `Print` and `Decode` (The Heart of Disassembly):**

* **`Print`:** Notice the use of `bufio.Writer` and `tabwriter`. This suggests the output is formatted for readability. The logic around filtering, iterating through symbols, and calling `Decode` becomes apparent. The caching mechanism for source code is also handled here.
* **`Decode`:** This function iterates through the code bytes, calling the appropriate `d.disasm` function based on the architecture. The handling of relocations is also done here, allowing for the display of relocation information.

**5. Examining the Architecture-Specific Disassemblers:**

The `disasm_*` functions are where the real disassembly magic happens. They use the `golang.org/x/arch/.../..asm` packages to decode individual instructions. The `gnuAsm` flag controls the output syntax. Observe the consistent pattern: decode the instruction, handle errors, format the output (optionally with GNU syntax), and return the disassembled text and instruction size. The `textReader` struct is interesting – it allows the architecture-specific disassemblers to read further bytes from the code stream if needed for complex instruction decoding (e.g., operands).

**6. Identifying Supported Architectures:**

The `disasms` and `byteOrders` maps explicitly list the supported architectures.

**7. Reasoning About Go Features Implemented:**

Based on the functionality, the most prominent Go feature being implemented is **binary code analysis and manipulation**. Specifically, this code is for *disassembling* compiled Go binaries, which is the reverse process of compilation.

**8. Constructing the Go Example:**

To demonstrate the use, we need a simple Go program to compile and then disassemble. The example should show the basic steps of opening the executable, creating a `Disasm` instance, and calling `Print`. Consider adding filtering and the `printCode` flag to show more advanced usage.

**9. Inferring Command-Line Argument Handling (Although Not Directly Present):**

While the provided code doesn't *directly* handle command-line arguments, we can infer how it *would* be used in a tool like `go tool objdump`. The `filter` argument to `Print` suggests a command-line flag to filter functions. The `start` and `end` arguments could correspond to address ranges provided on the command line. The `printCode` and `gnuAsm` flags likely correspond to command-line options as well.

**10. Spotting Potential User Errors:**

Consider common pitfalls when working with disassemblers:

* **Incorrect file path:**  The most basic error.
* **Disassembling non-executable files:**  The code expects a valid Go object file.
* **Filtering with incorrect regular expressions:** If the user intends to filter but uses a wrong regex.
* **Misunderstanding the output format:**  New users might not immediately grasp the meaning of the address, byte code, and disassembled instruction.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe it's just about reading executable files.
* **Correction:** Realized the core purpose is *disassembly*, which involves interpreting the machine code.
* **Initial thought:**  The `lookup` function is just for finding symbol names.
* **Refinement:**  Recognized that it's crucial for resolving addresses in instructions to meaningful symbol names.
* **Initial thought:**  The `FileCache` is just a nice-to-have.
* **Refinement:** Understood its importance for performance, especially when dealing with large codebases and displaying source.
* **Considered the connection to `go tool objdump`:**  This helps to contextualize the code and imagine its real-world usage.

By following these steps, iteratively refining understanding, and connecting the code to its broader purpose, we arrive at a comprehensive explanation of the `disasm.go` file.
这段代码是 Go 语言的 `cmd/internal/disasm` 包的一部分，它的主要功能是为 Go 语言编译后的二进制文件（或对象文件）提供**反汇编**的能力。简单来说，就是将机器码转换回人类可读的汇编代码。

**具体功能列举:**

1. **加载和解析二进制文件信息:**
   - `DisasmForFile` 和 `disasmForEntry` 函数负责读取和解析 Go 编译后的文件（通过 `cmd/internal/objfile` 包）。
   - 它提取出符号表 (`syms`)，PC-Line 表 (`pcln`)，代码段（`.text` 段的字节 `text`），代码段的起始和结束地址 (`textStart`, `textEnd`)，以及目标架构 (`goarch`)。

2. **根据架构选择合适的反汇编器:**
   - 它使用 `disasms` 这个 map 来存储不同架构（如 `386`, `amd64`, `arm`, `arm64` 等）对应的反汇编函数 (`disasmFunc`)。
   - `byteOrders` map 存储了不同架构的字节序，这对于正确解析指令至关重要。

3. **查找符号:**
   - `lookup` 函数接收一个内存地址，然后在符号表中查找包含该地址的符号名和符号的起始地址。这用于在反汇编输出中将地址关联到函数名或变量名。

4. **缓存源代码文件内容:**
   - `CachedFile` 和 `FileCache` 结构体实现了一个简单的 LRU (Least Recently Used) 缓存，用于存储源代码文件的内容。
   - `Line` 方法用于根据文件名和行号从缓存中获取源代码行的内容。如果文件不在缓存中，则会读取并添加到缓存。这用于在反汇编输出中穿插显示对应的源代码。

5. **格式化输出反汇编代码:**
   - `Print` 函数是主要的输出函数。它接收一个 `io.Writer`，以及可选的函数名过滤器 (`filter`)，起始和结束地址 (`start`, `end`)，是否打印源代码 (`printCode`)，以及是否使用 GNU 风格的汇编语法 (`gnuAsm`)。
   - 它使用 `tabwriter` 来格式化输出，使其对齐和易读。
   - 对于每个函数，它会遍历其代码范围，并调用 `Decode` 函数进行反汇编。

6. **核心反汇编逻辑:**
   - `Decode` 函数接收起始和结束地址，重定位信息 (`relocs`)，GNU 汇编语法标志，以及一个回调函数 `f`。
   - 它遍历代码段的指定范围，调用与当前架构对应的反汇编函数 (`d.disasm`) 来解码每条指令。
   - 它还处理重定位信息，将重定位条目添加到反汇编输出中。
   - 对于每条反汇编的指令，它会调用回调函数 `f`，传递指令的地址、大小、对应的源代码文件名和行号，以及反汇编后的文本。

7. **架构特定的反汇编实现:**
   - `disasm_386`, `disasm_amd64`, `disasm_arm`, `disasm_arm64`, `disasm_loong64`, `disasm_ppc64`, `disasm_riscv64`, `disasm_s390x` 等函数是针对不同 CPU 架构的具体反汇编实现。
   - 它们使用 `golang.org/x/arch` 下对应架构的汇编库（如 `golang.org/x/arch/x86/x86asm`）来解码机器指令。
   - 它们将解码后的指令格式化成可读的汇编代码，可以选择使用 Go 风格或 GNU 风格的语法。

**它是什么 Go 语言功能的实现？**

这个包主要实现了 Go 语言的 **二进制代码分析和操作** 的功能，更具体地说，是实现了 **反汇编** 的功能。反汇编是理解程序底层执行逻辑的重要手段，尤其是在调试、性能分析、安全审计等方面。

**Go 代码举例说明:**

假设我们有一个简单的 Go 程序 `main.go`:

```go
package main

import "fmt"

func add(a, b int) int {
	return a + b
}

func main() {
	x := 10
	y := 20
	sum := add(x, y)
	fmt.Println(sum)
}
```

我们可以编译它：

```bash
go build -o main main.go
```

然后，可以使用 `cmd/internal/disasm` 包（虽然它不是一个可以直接运行的程序，但可以被其他工具使用，比如 `go tool objdump`）来反汇编这个 `main` 文件。  为了演示其功能，我们可以假设我们已经有了一个使用该包的工具，它会执行类似下面的操作：

```go
package main

import (
	"fmt"
	"os"
	"regexp"

	"cmd/internal/disasm"
	"cmd/internal/objfile"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: disassembler <binary>")
		return
	}

	filename := os.Args[1]
	f, err := objfile.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer f.Close()

	d, err := disasm.DisasmForFile(f)
	if err != nil {
		fmt.Println("Error creating disassembler:", err)
		return
	}

	// 反汇编整个 .text 段
	d.Print(os.Stdout, nil, d.textStart, d.textEnd, true, false)
}
```

**假设的输入与输出:**

假设我们运行上面的 `disassembler main`，并且 `main` 编译后的架构是 `amd64`。  输出可能会类似于：

```
TEXT main.add(SB) /path/to/main.go
		/path/to/main.go:5		0x1000		488955f0	MOVQ	BP, -0x10(SP)
		/path/to/main.go:5		0x1004		488b6500	MOVQ	0(BP), SP
		/path/to/main.go:6		0x1008		8b4508		MOVL	0x8(BP), AX
		/path/to/main.go:6		0x100b		014510		ADDL	0x10(BP), AX
		/path/to/main.go:7		0x100e		8945f8		MOVL	AX, -0x8(BP)
		/path/to/main.go:7		0x1011		488b65f0	MOVQ	-0x10(BP), SP
		/path/to/main.go:7		0x1015		5d		POPQ	BP
		/path/to/main.go:7		0x1016		c3		RET

TEXT main.main(SB) /path/to/main.go
		/path/to/main.go:10		0x1017		48896c2418	MOVQ	BP, 0x18(SP)
		/path/to/main.go:10		0x101c		4881ec38000000	SUBQ	$0x38, SP
		/path/to/main.go:11		0x1023		c74424200a000000	MOVL	$0xa, 0x20(SP)
		/path/to/main.go:12		0x102b		c744242414000000	MOVL	$0x14, 0x24(SP)
		/path/to/main.go:13		0x1033		8b442420	MOVL	0x20(SP), AX
		/path/to/main.go:13		0x1037		8b4c2424	MOVL	0x24(SP), CX
		/path/to/main.go:13		0x103b		89442428	MOVL	AX, 0x28(SP)
		/path/to/main.go:13		0x103f		894c242c	MOVL	CX, 0x2c(SP)
		/path/to/main.go:13		0x1043		e8d8ffffff	CALL	main.add(SB)
		/path/to/main.go:13		0x1048		89442430	MOVL	AX, 0x30(SP)
		/path/to/main.go:14		0x104c		8b442430	MOVL	0x30(SP), AX
		/path/to/main.go:14		0x1050		488d0dabcdef01	LEAQ	runtime.rodata(SB), CX // 指向 runtime.rodata 的地址 (示例)
		/path/to/main.go:14		0x1057		48894c2408	MOVQ	CX, 0x8(SP)
		/path/to/main.go:14		0x105c		890424		MOVL	AX, 0(SP)
		/path/to/main.go:14		0x105f		e8bcfeffff	CALL	fmt.Println(SB)
		/path/to/main.go:15		0x1064		488b6c2418	MOVQ	0x18(SP), BP
		/path/to/main.go:15		0x1069		4881c438000000	ADDQ	$0x38, SP
		/path/to/main.go:15		0x1070		c3		RET
```

**命令行参数的具体处理:**

虽然这段代码本身没有直接处理命令行参数，但 `Print` 函数的设计暗示了它可能被一个命令行工具使用，该工具可能会传递以下参数：

* **要反汇编的文件名:**  通过 `objfile.Open` 函数加载。
* **`-filter=<regexp>`:** 对应 `Print` 函数的 `filter` 参数，用于过滤要显示反汇编结果的函数。
* **`-start=<address>` 和 `-end=<address>`:** 对应 `Print` 函数的 `start` 和 `end` 参数，用于指定要反汇编的代码范围。
* **`-S` 或 `--source`:** 对应 `Print` 函数的 `printCode` 参数，用于控制是否显示源代码。
* **`-gnu`:** 对应 `Print` 函数的 `gnuAsm` 参数，用于选择 GNU 风格的汇编语法。

例如，像 `go tool objdump -S main` 这样的命令，背后的实现就可能使用了 `cmd/internal/disasm` 包，并将 `-S` 标志传递给 `Print` 函数的 `printCode` 参数。

**使用者易犯错的点:**

1. **传递非 Go 可执行文件或对象文件:** `DisasmForFile` 会尝试解析文件结构，如果文件格式不正确，会返回错误。

   ```go
   // 假设尝试反汇编一个文本文件
   f, err := objfile.Open("some_text_file.txt")
   if err != nil {
       fmt.Println(err) // 可能输出类似 "not a valid object file" 的错误
   }
   ```

2. **使用不正确的正则表达式进行过滤:** 如果 `filter` 参数传入了错误的正则表达式，可能导致没有输出，或者输出了意料之外的内容。

   ```go
   // 假设只想查看 `main` 函数，但正则表达式写错了
   filter := regexp.MustCompile("mai.") // 错误的正则表达式
   d.Print(os.Stdout, filter, d.textStart, d.textEnd, false, false)
   ```

3. **指定的起始和结束地址超出代码段范围:**  虽然 `Print` 函数内部会做一些边界检查，但如果用户传递的地址严重超出范围，可能不会得到预期的结果。

   ```go
   // 假设代码段范围是 0x1000 到 0x2000
   d.Print(os.Stdout, nil, 0x5000, 0x6000, false, false) // 很可能没有输出
   ```

总而言之，`cmd/internal/disasm` 包是 Go 语言工具链中用于理解程序底层行为的关键组件，它提供了强大的反汇编能力，并被诸如 `go tool objdump` 这样的工具所使用。

Prompt: 
```
这是路径为go/src/cmd/internal/disasm/disasm.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package disasm provides disassembly routines.
//
// It is broken out from cmd/internal/objfile so tools that don't need
// disassembling don't need to depend on x/arch disassembler code.
package disasm

import (
	"bufio"
	"bytes"
	"container/list"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"

	"cmd/internal/objfile"
	"cmd/internal/src"

	"golang.org/x/arch/arm/armasm"
	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/loong64/loong64asm"
	"golang.org/x/arch/ppc64/ppc64asm"
	"golang.org/x/arch/riscv64/riscv64asm"
	"golang.org/x/arch/s390x/s390xasm"
	"golang.org/x/arch/x86/x86asm"
)

// Disasm is a disassembler for a given File.
type Disasm struct {
	syms      []objfile.Sym    // symbols in file, sorted by address
	pcln      objfile.Liner    // pcln table
	text      []byte           // bytes of text segment (actual instructions)
	textStart uint64           // start PC of text
	textEnd   uint64           // end PC of text
	goarch    string           // GOARCH string
	disasm    disasmFunc       // disassembler function for goarch
	byteOrder binary.ByteOrder // byte order for goarch
}

// DisasmForFile returns a disassembler for the file f.
func DisasmForFile(f *objfile.File) (*Disasm, error) {
	return disasmForEntry(f.Entries()[0])
}

func disasmForEntry(e *objfile.Entry) (*Disasm, error) {
	syms, err := e.Symbols()
	if err != nil {
		return nil, err
	}

	pcln, err := e.PCLineTable()
	if err != nil {
		return nil, err
	}

	textStart, textBytes, err := e.Text()
	if err != nil {
		return nil, err
	}

	goarch := e.GOARCH()
	disasm := disasms[goarch]
	byteOrder := byteOrders[goarch]
	if disasm == nil || byteOrder == nil {
		return nil, fmt.Errorf("unsupported architecture %q", goarch)
	}

	// Filter out section symbols, overwriting syms in place.
	keep := syms[:0]
	for _, sym := range syms {
		switch sym.Name {
		case "runtime.text", "text", "_text", "runtime.etext", "etext", "_etext":
			// drop
		default:
			keep = append(keep, sym)
		}
	}
	syms = keep
	d := &Disasm{
		syms:      syms,
		pcln:      pcln,
		text:      textBytes,
		textStart: textStart,
		textEnd:   textStart + uint64(len(textBytes)),
		goarch:    goarch,
		disasm:    disasm,
		byteOrder: byteOrder,
	}

	return d, nil
}

// lookup finds the symbol name containing addr.
func (d *Disasm) lookup(addr uint64) (name string, base uint64) {
	i := sort.Search(len(d.syms), func(i int) bool { return addr < d.syms[i].Addr })
	if i > 0 {
		s := d.syms[i-1]
		if s.Addr != 0 && s.Addr <= addr && addr < s.Addr+uint64(s.Size) {
			return s.Name, s.Addr
		}
	}
	return "", 0
}

// base returns the final element in the path.
// It works on both Windows and Unix paths,
// regardless of host operating system.
func base(path string) string {
	path = path[strings.LastIndex(path, "/")+1:]
	path = path[strings.LastIndex(path, `\`)+1:]
	return path
}

// CachedFile contains the content of a file split into lines.
type CachedFile struct {
	FileName string
	Lines    [][]byte
}

// FileCache is a simple LRU cache of file contents.
type FileCache struct {
	files  *list.List
	maxLen int
}

// NewFileCache returns a FileCache which can contain up to maxLen cached file contents.
func NewFileCache(maxLen int) *FileCache {
	return &FileCache{
		files:  list.New(),
		maxLen: maxLen,
	}
}

// Line returns the source code line for the given file and line number.
// If the file is not already cached, reads it, inserts it into the cache,
// and removes the least recently used file if necessary.
// If the file is in cache, it is moved to the front of the list.
func (fc *FileCache) Line(filename string, line int) ([]byte, error) {
	if filepath.Ext(filename) != ".go" {
		return nil, nil
	}

	// Clean filenames returned by src.Pos.SymFilename()
	// or src.PosBase.SymFilename() removing
	// the leading src.FileSymPrefix.
	filename = strings.TrimPrefix(filename, src.FileSymPrefix)

	// Expand literal "$GOROOT" rewritten by obj.AbsFile()
	filename = filepath.Clean(os.ExpandEnv(filename))

	var cf *CachedFile
	var e *list.Element

	for e = fc.files.Front(); e != nil; e = e.Next() {
		cf = e.Value.(*CachedFile)
		if cf.FileName == filename {
			break
		}
	}

	if e == nil {
		content, err := os.ReadFile(filename)
		if err != nil {
			return nil, err
		}

		cf = &CachedFile{
			FileName: filename,
			Lines:    bytes.Split(content, []byte{'\n'}),
		}
		fc.files.PushFront(cf)

		if fc.files.Len() >= fc.maxLen {
			fc.files.Remove(fc.files.Back())
		}
	} else {
		fc.files.MoveToFront(e)
	}

	// because //line directives can be out-of-range. (#36683)
	if line-1 >= len(cf.Lines) || line-1 < 0 {
		return nil, nil
	}

	return cf.Lines[line-1], nil
}

// Print prints a disassembly of the file to w.
// If filter is non-nil, the disassembly only includes functions with names matching filter.
// If printCode is true, the disassembly includes corresponding source lines.
// The disassembly only includes functions that overlap the range [start, end).
func (d *Disasm) Print(w io.Writer, filter *regexp.Regexp, start, end uint64, printCode bool, gnuAsm bool) {
	if start < d.textStart {
		start = d.textStart
	}
	if end > d.textEnd {
		end = d.textEnd
	}
	printed := false
	bw := bufio.NewWriter(w)

	var fc *FileCache
	if printCode {
		fc = NewFileCache(8)
	}

	tw := tabwriter.NewWriter(bw, 18, 8, 1, '\t', tabwriter.StripEscape)
	for _, sym := range d.syms {
		symStart := sym.Addr
		symEnd := sym.Addr + uint64(sym.Size)
		relocs := sym.Relocs
		if sym.Code != 'T' && sym.Code != 't' ||
			symStart < d.textStart ||
			symEnd <= start || end <= symStart ||
			filter != nil && !filter.MatchString(sym.Name) {
			continue
		}
		if printed {
			fmt.Fprintf(bw, "\n")
		}
		printed = true

		file, _, _ := d.pcln.PCToLine(sym.Addr)
		fmt.Fprintf(bw, "TEXT %s(SB) %s\n", sym.Name, file)

		if symEnd > end {
			symEnd = end
		}
		code := d.text[:end-d.textStart]

		var lastFile string
		var lastLine int

		d.Decode(symStart, symEnd, relocs, gnuAsm, func(pc, size uint64, file string, line int, text string) {
			i := pc - d.textStart

			if printCode {
				if file != lastFile || line != lastLine {
					if srcLine, err := fc.Line(file, line); err == nil {
						fmt.Fprintf(tw, "%s%s%s\n", []byte{tabwriter.Escape}, srcLine, []byte{tabwriter.Escape})
					}

					lastFile, lastLine = file, line
				}

				fmt.Fprintf(tw, "  %#x\t", pc)
			} else {
				fmt.Fprintf(tw, "  %s:%d\t%#x\t", base(file), line, pc)
			}

			if size%4 != 0 || d.goarch == "386" || d.goarch == "amd64" {
				// Print instruction as bytes.
				fmt.Fprintf(tw, "%x", code[i:i+size])
			} else {
				// Print instruction as 32-bit words.
				for j := uint64(0); j < size; j += 4 {
					if j > 0 {
						fmt.Fprintf(tw, " ")
					}
					fmt.Fprintf(tw, "%08x", d.byteOrder.Uint32(code[i+j:]))
				}
			}
			fmt.Fprintf(tw, "\t%s\t\n", text)
		})
		tw.Flush()
	}
	bw.Flush()
}

// Decode disassembles the text segment range [start, end), calling f for each instruction.
func (d *Disasm) Decode(start, end uint64, relocs []objfile.Reloc, gnuAsm bool, f func(pc, size uint64, file string, line int, text string)) {
	if start < d.textStart {
		start = d.textStart
	}
	if end > d.textEnd {
		end = d.textEnd
	}
	code := d.text[:end-d.textStart]
	lookup := d.lookup
	for pc := start; pc < end; {
		i := pc - d.textStart
		text, size := d.disasm(code[i:], pc, lookup, d.byteOrder, gnuAsm)
		file, line, _ := d.pcln.PCToLine(pc)
		sep := "\t"
		for len(relocs) > 0 && relocs[0].Addr < i+uint64(size) {
			text += sep + relocs[0].Stringer.String(pc-start)
			sep = " "
			relocs = relocs[1:]
		}
		f(pc, uint64(size), file, line, text)
		pc += uint64(size)
	}
}

type lookupFunc = func(addr uint64) (sym string, base uint64)
type disasmFunc func(code []byte, pc uint64, lookup lookupFunc, ord binary.ByteOrder, _ bool) (text string, size int)

func disasm_386(code []byte, pc uint64, lookup lookupFunc, _ binary.ByteOrder, gnuAsm bool) (string, int) {
	return disasm_x86(code, pc, lookup, 32, gnuAsm)
}

func disasm_amd64(code []byte, pc uint64, lookup lookupFunc, _ binary.ByteOrder, gnuAsm bool) (string, int) {
	return disasm_x86(code, pc, lookup, 64, gnuAsm)
}

func disasm_x86(code []byte, pc uint64, lookup lookupFunc, arch int, gnuAsm bool) (string, int) {
	inst, err := x86asm.Decode(code, arch)
	var text string
	size := inst.Len
	if err != nil || size == 0 || inst.Op == 0 {
		size = 1
		text = "?"
	} else {
		if gnuAsm {
			text = fmt.Sprintf("%-36s // %s", x86asm.GoSyntax(inst, pc, lookup), x86asm.GNUSyntax(inst, pc, nil))
		} else {
			text = x86asm.GoSyntax(inst, pc, lookup)
		}
	}
	return text, size
}

type textReader struct {
	code []byte
	pc   uint64
}

func (r textReader) ReadAt(data []byte, off int64) (n int, err error) {
	if off < 0 || uint64(off) < r.pc {
		return 0, io.EOF
	}
	d := uint64(off) - r.pc
	if d >= uint64(len(r.code)) {
		return 0, io.EOF
	}
	n = copy(data, r.code[d:])
	if n < len(data) {
		err = io.ErrUnexpectedEOF
	}
	return
}

func disasm_arm(code []byte, pc uint64, lookup lookupFunc, _ binary.ByteOrder, gnuAsm bool) (string, int) {
	inst, err := armasm.Decode(code, armasm.ModeARM)
	var text string
	size := inst.Len
	if err != nil || size == 0 || inst.Op == 0 {
		size = 4
		text = "?"
	} else if gnuAsm {
		text = fmt.Sprintf("%-36s // %s", armasm.GoSyntax(inst, pc, lookup, textReader{code, pc}), armasm.GNUSyntax(inst))
	} else {
		text = armasm.GoSyntax(inst, pc, lookup, textReader{code, pc})
	}
	return text, size
}

func disasm_arm64(code []byte, pc uint64, lookup lookupFunc, byteOrder binary.ByteOrder, gnuAsm bool) (string, int) {
	inst, err := arm64asm.Decode(code)
	var text string
	if err != nil || inst.Op == 0 {
		text = "?"
	} else if gnuAsm {
		text = fmt.Sprintf("%-36s // %s", arm64asm.GoSyntax(inst, pc, lookup, textReader{code, pc}), arm64asm.GNUSyntax(inst))
	} else {
		text = arm64asm.GoSyntax(inst, pc, lookup, textReader{code, pc})
	}
	return text, 4
}

func disasm_loong64(code []byte, pc uint64, lookup lookupFunc, byteOrder binary.ByteOrder, gnuAsm bool) (string, int) {
	inst, err := loong64asm.Decode(code)
	var text string
	if err != nil || inst.Op == 0 {
		text = "?"
	} else if gnuAsm {
		text = fmt.Sprintf("%-36s // %s", loong64asm.GoSyntax(inst, pc, lookup), loong64asm.GNUSyntax(inst))
	} else {
		text = loong64asm.GoSyntax(inst, pc, lookup)
	}
	return text, 4
}

func disasm_ppc64(code []byte, pc uint64, lookup lookupFunc, byteOrder binary.ByteOrder, gnuAsm bool) (string, int) {
	inst, err := ppc64asm.Decode(code, byteOrder)
	var text string
	size := inst.Len
	if err != nil || size == 0 {
		size = 4
		text = "?"
	} else {
		if gnuAsm {
			text = fmt.Sprintf("%-36s // %s", ppc64asm.GoSyntax(inst, pc, lookup), ppc64asm.GNUSyntax(inst, pc))
		} else {
			text = ppc64asm.GoSyntax(inst, pc, lookup)
		}
	}
	return text, size
}

func disasm_riscv64(code []byte, pc uint64, lookup lookupFunc, byteOrder binary.ByteOrder, gnuAsm bool) (string, int) {
	inst, err := riscv64asm.Decode(code)
	var text string
	if err != nil || inst.Op == 0 {
		text = "?"
	} else if gnuAsm {
		text = fmt.Sprintf("%-36s // %s", riscv64asm.GoSyntax(inst, pc, lookup, textReader{code, pc}), riscv64asm.GNUSyntax(inst))
	} else {
		text = riscv64asm.GoSyntax(inst, pc, lookup, textReader{code, pc})
	}
	return text, 4
}

func disasm_s390x(code []byte, pc uint64, lookup lookupFunc, _ binary.ByteOrder, gnuAsm bool) (string, int) {
	inst, err := s390xasm.Decode(code)
	var text string
	size := inst.Len
	if err != nil || size == 0 || inst.Op == 0 {
		size = 2
		text = "?"
	} else {
		if gnuAsm {
			text = fmt.Sprintf("%-36s // %s", s390xasm.GoSyntax(inst, pc, lookup), s390xasm.GNUSyntax(inst, pc))
		} else {
			text = s390xasm.GoSyntax(inst, pc, lookup)
		}
	}
	return text, size
}

var disasms = map[string]disasmFunc{
	"386":     disasm_386,
	"amd64":   disasm_amd64,
	"arm":     disasm_arm,
	"arm64":   disasm_arm64,
	"loong64": disasm_loong64,
	"ppc64":   disasm_ppc64,
	"ppc64le": disasm_ppc64,
	"riscv64": disasm_riscv64,
	"s390x":   disasm_s390x,
}

var byteOrders = map[string]binary.ByteOrder{
	"386":     binary.LittleEndian,
	"amd64":   binary.LittleEndian,
	"arm":     binary.LittleEndian,
	"arm64":   binary.LittleEndian,
	"loong64": binary.LittleEndian,
	"ppc64":   binary.BigEndian,
	"ppc64le": binary.LittleEndian,
	"riscv64": binary.LittleEndian,
	"s390x":   binary.BigEndian,
}

"""



```