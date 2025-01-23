Response:
Let's break down the thought process for analyzing the `position.go` file.

1. **Understand the Goal:** The request asks for the functionality of the code, potential Go feature implementation, code examples, command-line argument handling (if any), and common mistakes. The core task is to understand the purpose and usage of the `token` package's position-related types and functions.

2. **Initial Scan and Identification of Key Types:**  A quick scan reveals the central types: `Position`, `Pos`, `File`, and `FileSet`. These are the building blocks of source code location representation. Understanding these is paramount.

3. **`Position` Analysis:**
    * **Fields:** Note the `Filename`, `Offset`, `Line`, and `Column`. These directly map to the familiar concept of a source code location.
    * **Methods:**  `IsValid()` is straightforward. `String()` is important for human-readable output. The different output formats based on which fields are populated are key to understanding how `Position` is used.

4. **`Pos` Analysis:**
    * **Purpose:** The doc comment clearly states it's a *compact encoding* of a source position. This immediately suggests it's more efficient for storage and comparison than `Position`.
    * **Relationship to `FileSet` and `File`:** The explanation of the `[base, base+size]` range is crucial. It links `Pos` to a specific file within a `FileSet`. The mention of `File.Pos(offset)` and `FileSet.Position(p)` highlights the conversion mechanisms between `Pos` and `Position`.
    * **Comparison:**  The behavior of comparing `Pos` values across different files (based on file addition order) is a subtle but important detail.
    * **`NoPos`:**  Recognize this as the zero value, signifying an invalid or absent position.

5. **`File` Analysis:**
    * **Purpose:** Represents a single source file within a `FileSet`.
    * **Key Fields:** `name`, `base`, `size`, and the crucial `lines` slice (representing line start offsets). The `infos` slice is for handling `#line` directives.
    * **Core Functionality (Methods):**
        * **Basic Information:** `Name()`, `Base()`, `Size()`, `LineCount()`.
        * **Line Management:** `AddLine()`, `MergeLine()`, `Lines()`, `SetLines()`, `SetLinesForContent()`. These are central to mapping offsets to line numbers.
        * **Position Conversion (within a file):** `LineStart()`, `Pos()`, `Offset()`, `Line()`, `Position()`, `PositionFor()`. Notice the `adjusted` parameter relating to `#line` directives.
        * **`AddLineInfo` / `AddLineColumnInfo`:**  Understand their role in handling `#line` directives to remap positions.
        * **`unpack` and `position` (private):** Recognize these as the internal implementation details for converting offsets to `Position`, considering `#line` directives.

6. **`FileSet` Analysis:**
    * **Purpose:** Manages a collection of `File` objects. The central authority for mapping `Pos` values to `Position` values.
    * **Key Fields:** `base` (for allocating new file ranges) and `files` (the slice of managed files).
    * **Core Functionality (Methods):**
        * **Creation:** `NewFileSet()`.
        * **Adding Files:** `AddFile()`. Pay attention to the `base` argument and how `FileSet` manages it.
        * **Removing Files:** `RemoveFile()`.
        * **Iteration:** `Iterate()`.
        * **File Lookup:** `File()`. Note the caching mechanism (`last`).
        * **Position Conversion (across files):** `Position()`, `PositionFor()`. These methods delegate to the appropriate `File` object.
        * **`Base()`:**  Provides the recommended starting `base` for the next file.

7. **Inferring Go Feature Implementation:**  Based on the types and their functions, the most obvious inference is **lexical analysis and parsing**. The ability to track the precise location of tokens within source code is fundamental to these processes.

8. **Code Examples:**  Develop simple, illustrative examples showcasing the key functionalities:
    * Creating a `FileSet` and `File`.
    * Adding lines and getting line counts.
    * Converting between `Pos` and `Position`.
    * Using `#line` directives.

9. **Command-Line Arguments:**  Realize that this specific code snippet *doesn't* directly handle command-line arguments. The `token` package provides the *data structures* and *logic* for handling positions, but the actual reading of files and processing of command-line arguments would happen in other parts of a compiler or related tool.

10. **Common Mistakes:**  Think about how developers might misuse these types:
    * Incorrectly calculating or managing `Pos` values.
    * Assuming `Pos` values are globally unique without considering the `FileSet`.
    * Misunderstanding the effect of `#line` directives.
    * Mutating the `lines` slice returned by `File.Lines()`.

11. **Structuring the Answer:** Organize the information logically:
    * Start with a general overview of the file's purpose.
    * Detail the functionality of each key type (`Position`, `Pos`, `File`, `FileSet`).
    * Provide a clear inference of the Go feature.
    * Include practical code examples with inputs and outputs.
    * Explicitly state the lack of direct command-line argument handling.
    * List potential common mistakes.

12. **Language and Formatting:**  Use clear and concise Chinese. Format the code examples for readability.

**Self-Correction/Refinement:**

* **Initial Thought:**  Perhaps the code directly handles file reading.
* **Correction:** Realize that the `token` package focuses on *representing* positions, not necessarily the I/O aspects. File reading would be handled by a higher-level component.
* **Initial Thought:** Maybe the comparison of `Pos` values is simply based on their integer value.
* **Correction:**  Note the crucial detail that cross-file `Pos` comparison depends on the order of file addition to the `FileSet`.

By following these steps, systematically analyzing the code, and thinking about its intended use, we can arrive at a comprehensive and accurate answer to the request.
这段代码是 Go 语言 `go/token` 包中 `position.go` 文件的一部分，它定义了表示源代码中位置的关键类型和方法。其主要功能可以归纳为：

**1. 表示源代码的位置信息:**

* **`Position` 结构体:**  用于表示源代码中的具体位置，包含文件名 (`Filename`)、从文件开始的字节偏移量 (`Offset`)、行号 (`Line`) 和列号 (`Column`)。
* **`Pos` 类型:**  一个整数类型，用于在 `FileSet` 中更紧凑地表示源代码位置。它实际上是相对于文件在 `FileSet` 中的起始偏移量的偏移。

**2. 管理一组源代码文件及其位置信息:**

* **`File` 结构体:**  代表一个源代码文件，存储了文件名、在 `FileSet` 中的起始偏移量 (`base`)、文件大小 (`size`) 以及用于快速查找行号的行偏移量表 (`lines`) 和用于处理 `//line` 指令的额外位置信息 (`infos`)。
* **`FileSet` 结构体:**  表示一组源代码文件，用于统一管理这些文件的位置信息。它维护了已添加的文件列表，并负责为新添加的文件分配不冲突的 `Pos` 值范围。

**3. 在 `Pos` 和 `Position` 之间进行转换:**

* **`File.Pos(offset int) Pos`:**  给定文件内的字节偏移量，返回对应的 `Pos` 值。
* **`File.Offset(p Pos) int`:** 给定 `Pos` 值，返回其在文件内的字节偏移量。
* **`File.Position(p Pos) Position`:** 给定 `Pos` 值，返回更详细的 `Position` 结构体，包含文件名、行号和列号。
* **`FileSet.Position(p Pos) Position`:**  给定一个全局的 `Pos` 值，确定其所属的文件，并返回对应的 `Position` 结构体。

**4. 管理文件的行信息:**

* **`File.AddLine(offset int)`:**  添加一个新行的起始字节偏移量。
* **`File.MergeLine(line int)`:**  将指定行与下一行合并，通常用于处理连接符。
* **`File.SetLines(lines []int) bool`:**  设置文件的完整行偏移量表。
* **`File.SetLinesForContent(content []byte)`:**  根据文件内容自动生成行偏移量表。
* **`File.LineStart(line int) Pos`:**  返回指定行开始的 `Pos` 值。

**5. 处理 `//line` 指令:**

* **`File.AddLineInfo(offset int, filename string, line int)` 和 `File.AddLineColumnInfo(offset int, filename string, line, column int)`:**  用于记录 `//line` 指令提供的位置信息，以便在后续的位置转换中进行调整。

**可以推理出它是什么 go 语言功能的实现：**

这个文件是 Go 语言 **词法分析器（Scanner）和语法分析器（Parser）** 的基础组成部分。在编译 Go 代码的过程中，首先需要将源代码分解成一个个的词法单元（token），并识别出它们的类型和值。同时，记录每个 token 在源代码中的位置对于错误报告和代码导航等功能至关重要。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"go/token"
)

func main() {
	fset := token.NewFileSet()
	// 假设我们有一个名为 "example.go" 的文件，内容如下：
	// package main
	//
	// import "fmt"
	//
	// func main() {
	// 	fmt.Println("Hello")
	// }
	file := fset.AddFile("example.go", 1, len("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Println(\"Hello\")\n}\n"))

	// 添加行信息 (通常 scanner 会自动完成)
	file.SetLines([]int{0, 13, 15, 29, 31, 45})

	// 假设我们有一个 token 的 Pos 值
	// 这里的 Pos 值需要根据实际的词法分析结果来确定
	// 假设 "fmt" 这个 token 的起始位置在文件中的偏移量是 15
	pos := file.Pos(15)

	// 将 Pos 转换为 Position
	position := fset.Position(pos)
	fmt.Printf("Token at position: %s\n", position.String()) // 输出: example.go:3:10

	// 获取某一行的起始 Pos
	lineStartPos := file.LineStart(5)
	lineStartPosition := fset.Position(lineStartPos)
	fmt.Printf("Start of line 5: %s\n", lineStartPosition.String()) // 输出: example.go:5:1

	// 模拟 //line 指令
	file.AddLineInfo(29, "another_file.go", 10) // 在偏移量 29 处，声明后续位置来自 another_file.go 的第 10 行
	posAfterLineDirective := file.Pos(35)
	positionAfterLineDirective := fset.Position(posAfterLineDirective)
	fmt.Printf("Position after //line directive: %s\n", positionAfterLineDirective.String()) // 输出: another_file.go:11:3 (假设偏移量 35 在 func 关键字的 'f')
}
```

**假设的输入与输出:**

在上面的代码例子中，我们假设了 `example.go` 文件的内容和某些 token 的位置。实际的输入将是 Go 源代码文件的内容，而输出将是根据这些内容生成的 `Position` 信息。

**命令行参数的具体处理:**

这个文件本身 **不涉及** 命令行参数的处理。`go/token` 包是 Go 语言工具链中的一个基础库，它只负责定义和管理源代码的位置信息。具体的命令行参数处理通常发生在更上层的工具中，例如 `go build`, `go run`, `gofmt` 等。这些工具会使用 `go/token` 包来记录和报告错误位置等信息。

**使用者易犯错的点:**

1. **误解 `Pos` 的含义:**  `Pos` 值本身并不包含文件名、行号和列号等信息，它只是一个相对于 `FileSet` 中某个文件的起始偏移量的整数。需要通过 `FileSet` 或 `File` 的方法才能将其转换为 `Position`。
    ```go
    // 错误示例
    var p token.Pos = 10
    // fmt.Println(p.Filename) // 编译错误：token.Pos 没有 Filename 字段

    // 正确示例
    fset := token.NewFileSet()
    file := fset.AddFile("myfile.go", 1, 100)
    pos := file.Pos(5)
    position := fset.Position(pos)
    fmt.Println(position.Filename) // 输出: myfile.go
    ```

2. **不正确地使用 `FileSet.Base()`:**  添加新文件时，应该使用 `FileSet.Base()` 返回的值作为新文件的 `base` 参数，以确保文件之间的 `Pos` 值范围不冲突。手动指定可能导致 `Pos` 值重叠，从而引起混乱。
    ```go
    fset := token.NewFileSet()
    // 正确：使用 fset.Base()
    file1 := fset.AddFile("file1.go", fset.Base(), 100)
    file2 := fset.AddFile("file2.go", fset.Base(), 50)

    // 错误：手动指定 base 可能导致冲突
    // file3 := fset.AddFile("file3.go", 1, 20) // 如果 file1 的 base 也是 1，则会冲突
    ```

3. **忘记考虑 `//line` 指令的影响:**  在处理包含 `//line` 指令的源代码时，需要使用 `File.PositionFor(pos, true)` 或 `FileSet.PositionFor(pos, true)` 来获取根据指令调整后的位置信息。默认的 `File.Position(pos)` 和 `FileSet.Position(pos)` 不会考虑这些指令。

总而言之，`go/token/position.go` 文件定义了 Go 语言中表示和管理源代码位置的基础设施，为词法分析、语法分析以及后续的编译和代码处理过程提供了关键的支持。理解其核心概念和使用方法对于开发 Go 语言工具至关重要。

### 提示词
```
这是路径为go/src/go/token/position.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package token

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
)

// If debug is set, invalid offset and position values cause a panic
// (go.dev/issue/57490).
const debug = false

// -----------------------------------------------------------------------------
// Positions

// Position describes an arbitrary source position
// including the file, line, and column location.
// A Position is valid if the line number is > 0.
type Position struct {
	Filename string // filename, if any
	Offset   int    // offset, starting at 0
	Line     int    // line number, starting at 1
	Column   int    // column number, starting at 1 (byte count)
}

// IsValid reports whether the position is valid.
func (pos *Position) IsValid() bool { return pos.Line > 0 }

// String returns a string in one of several forms:
//
//	file:line:column    valid position with file name
//	file:line           valid position with file name but no column (column == 0)
//	line:column         valid position without file name
//	line                valid position without file name and no column (column == 0)
//	file                invalid position with file name
//	-                   invalid position without file name
func (pos Position) String() string {
	s := pos.Filename
	if pos.IsValid() {
		if s != "" {
			s += ":"
		}
		s += strconv.Itoa(pos.Line)
		if pos.Column != 0 {
			s += fmt.Sprintf(":%d", pos.Column)
		}
	}
	if s == "" {
		s = "-"
	}
	return s
}

// Pos is a compact encoding of a source position within a file set.
// It can be converted into a [Position] for a more convenient, but much
// larger, representation.
//
// The Pos value for a given file is a number in the range [base, base+size],
// where base and size are specified when a file is added to the file set.
// The difference between a Pos value and the corresponding file base
// corresponds to the byte offset of that position (represented by the Pos value)
// from the beginning of the file. Thus, the file base offset is the Pos value
// representing the first byte in the file.
//
// To create the Pos value for a specific source offset (measured in bytes),
// first add the respective file to the current file set using [FileSet.AddFile]
// and then call [File.Pos](offset) for that file. Given a Pos value p
// for a specific file set fset, the corresponding [Position] value is
// obtained by calling fset.Position(p).
//
// Pos values can be compared directly with the usual comparison operators:
// If two Pos values p and q are in the same file, comparing p and q is
// equivalent to comparing the respective source file offsets. If p and q
// are in different files, p < q is true if the file implied by p was added
// to the respective file set before the file implied by q.
type Pos int

// The zero value for [Pos] is NoPos; there is no file and line information
// associated with it, and NoPos.IsValid() is false. NoPos is always
// smaller than any other [Pos] value. The corresponding [Position] value
// for NoPos is the zero value for [Position].
const NoPos Pos = 0

// IsValid reports whether the position is valid.
func (p Pos) IsValid() bool {
	return p != NoPos
}

// -----------------------------------------------------------------------------
// File

// A File is a handle for a file belonging to a [FileSet].
// A File has a name, size, and line offset table.
type File struct {
	name string // file name as provided to AddFile
	base int    // Pos value range for this file is [base...base+size]
	size int    // file size as provided to AddFile

	// lines and infos are protected by mutex
	mutex sync.Mutex
	lines []int // lines contains the offset of the first character for each line (the first entry is always 0)
	infos []lineInfo
}

// Name returns the file name of file f as registered with AddFile.
func (f *File) Name() string {
	return f.name
}

// Base returns the base offset of file f as registered with AddFile.
func (f *File) Base() int {
	return f.base
}

// Size returns the size of file f as registered with AddFile.
func (f *File) Size() int {
	return f.size
}

// LineCount returns the number of lines in file f.
func (f *File) LineCount() int {
	f.mutex.Lock()
	n := len(f.lines)
	f.mutex.Unlock()
	return n
}

// AddLine adds the line offset for a new line.
// The line offset must be larger than the offset for the previous line
// and smaller than the file size; otherwise the line offset is ignored.
func (f *File) AddLine(offset int) {
	f.mutex.Lock()
	if i := len(f.lines); (i == 0 || f.lines[i-1] < offset) && offset < f.size {
		f.lines = append(f.lines, offset)
	}
	f.mutex.Unlock()
}

// MergeLine merges a line with the following line. It is akin to replacing
// the newline character at the end of the line with a space (to not change the
// remaining offsets). To obtain the line number, consult e.g. [Position.Line].
// MergeLine will panic if given an invalid line number.
func (f *File) MergeLine(line int) {
	if line < 1 {
		panic(fmt.Sprintf("invalid line number %d (should be >= 1)", line))
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if line >= len(f.lines) {
		panic(fmt.Sprintf("invalid line number %d (should be < %d)", line, len(f.lines)))
	}
	// To merge the line numbered <line> with the line numbered <line+1>,
	// we need to remove the entry in lines corresponding to the line
	// numbered <line+1>. The entry in lines corresponding to the line
	// numbered <line+1> is located at index <line>, since indices in lines
	// are 0-based and line numbers are 1-based.
	copy(f.lines[line:], f.lines[line+1:])
	f.lines = f.lines[:len(f.lines)-1]
}

// Lines returns the effective line offset table of the form described by [File.SetLines].
// Callers must not mutate the result.
func (f *File) Lines() []int {
	f.mutex.Lock()
	lines := f.lines
	f.mutex.Unlock()
	return lines
}

// SetLines sets the line offsets for a file and reports whether it succeeded.
// The line offsets are the offsets of the first character of each line;
// for instance for the content "ab\nc\n" the line offsets are {0, 3}.
// An empty file has an empty line offset table.
// Each line offset must be larger than the offset for the previous line
// and smaller than the file size; otherwise SetLines fails and returns
// false.
// Callers must not mutate the provided slice after SetLines returns.
func (f *File) SetLines(lines []int) bool {
	// verify validity of lines table
	size := f.size
	for i, offset := range lines {
		if i > 0 && offset <= lines[i-1] || size <= offset {
			return false
		}
	}

	// set lines table
	f.mutex.Lock()
	f.lines = lines
	f.mutex.Unlock()
	return true
}

// SetLinesForContent sets the line offsets for the given file content.
// It ignores position-altering //line comments.
func (f *File) SetLinesForContent(content []byte) {
	var lines []int
	line := 0
	for offset, b := range content {
		if line >= 0 {
			lines = append(lines, line)
		}
		line = -1
		if b == '\n' {
			line = offset + 1
		}
	}

	// set lines table
	f.mutex.Lock()
	f.lines = lines
	f.mutex.Unlock()
}

// LineStart returns the [Pos] value of the start of the specified line.
// It ignores any alternative positions set using [File.AddLineColumnInfo].
// LineStart panics if the 1-based line number is invalid.
func (f *File) LineStart(line int) Pos {
	if line < 1 {
		panic(fmt.Sprintf("invalid line number %d (should be >= 1)", line))
	}
	f.mutex.Lock()
	defer f.mutex.Unlock()
	if line > len(f.lines) {
		panic(fmt.Sprintf("invalid line number %d (should be < %d)", line, len(f.lines)))
	}
	return Pos(f.base + f.lines[line-1])
}

// A lineInfo object describes alternative file, line, and column
// number information (such as provided via a //line directive)
// for a given file offset.
type lineInfo struct {
	// fields are exported to make them accessible to gob
	Offset       int
	Filename     string
	Line, Column int
}

// AddLineInfo is like [File.AddLineColumnInfo] with a column = 1 argument.
// It is here for backward-compatibility for code prior to Go 1.11.
func (f *File) AddLineInfo(offset int, filename string, line int) {
	f.AddLineColumnInfo(offset, filename, line, 1)
}

// AddLineColumnInfo adds alternative file, line, and column number
// information for a given file offset. The offset must be larger
// than the offset for the previously added alternative line info
// and smaller than the file size; otherwise the information is
// ignored.
//
// AddLineColumnInfo is typically used to register alternative position
// information for line directives such as //line filename:line:column.
func (f *File) AddLineColumnInfo(offset int, filename string, line, column int) {
	f.mutex.Lock()
	if i := len(f.infos); (i == 0 || f.infos[i-1].Offset < offset) && offset < f.size {
		f.infos = append(f.infos, lineInfo{offset, filename, line, column})
	}
	f.mutex.Unlock()
}

// fixOffset fixes an out-of-bounds offset such that 0 <= offset <= f.size.
func (f *File) fixOffset(offset int) int {
	switch {
	case offset < 0:
		if !debug {
			return 0
		}
	case offset > f.size:
		if !debug {
			return f.size
		}
	default:
		return offset
	}

	// only generate this code if needed
	if debug {
		panic(fmt.Sprintf("offset %d out of bounds [%d, %d] (position %d out of bounds [%d, %d])",
			0 /* for symmetry */, offset, f.size,
			f.base+offset, f.base, f.base+f.size))
	}
	return 0
}

// Pos returns the Pos value for the given file offset.
//
// If offset is negative, the result is the file's start
// position; if the offset is too large, the result is
// the file's end position (see also go.dev/issue/57490).
//
// The following invariant, though not true for Pos values
// in general, holds for the result p:
// f.Pos(f.Offset(p)) == p.
func (f *File) Pos(offset int) Pos {
	return Pos(f.base + f.fixOffset(offset))
}

// Offset returns the offset for the given file position p.
//
// If p is before the file's start position (or if p is NoPos),
// the result is 0; if p is past the file's end position,
// the result is the file size (see also go.dev/issue/57490).
//
// The following invariant, though not true for offset values
// in general, holds for the result offset:
// f.Offset(f.Pos(offset)) == offset
func (f *File) Offset(p Pos) int {
	return f.fixOffset(int(p) - f.base)
}

// Line returns the line number for the given file position p;
// p must be a [Pos] value in that file or [NoPos].
func (f *File) Line(p Pos) int {
	return f.Position(p).Line
}

func searchLineInfos(a []lineInfo, x int) int {
	i, found := slices.BinarySearchFunc(a, x, func(a lineInfo, x int) int {
		return cmp.Compare(a.Offset, x)
	})
	if !found {
		// We want the lineInfo containing x, but if we didn't
		// find x then i is the next one.
		i--
	}
	return i
}

// unpack returns the filename and line and column number for a file offset.
// If adjusted is set, unpack will return the filename and line information
// possibly adjusted by //line comments; otherwise those comments are ignored.
func (f *File) unpack(offset int, adjusted bool) (filename string, line, column int) {
	f.mutex.Lock()
	filename = f.name
	if i := searchInts(f.lines, offset); i >= 0 {
		line, column = i+1, offset-f.lines[i]+1
	}
	if adjusted && len(f.infos) > 0 {
		// few files have extra line infos
		if i := searchLineInfos(f.infos, offset); i >= 0 {
			alt := &f.infos[i]
			filename = alt.Filename
			if i := searchInts(f.lines, alt.Offset); i >= 0 {
				// i+1 is the line at which the alternative position was recorded
				d := line - (i + 1) // line distance from alternative position base
				line = alt.Line + d
				if alt.Column == 0 {
					// alternative column is unknown => relative column is unknown
					// (the current specification for line directives requires
					// this to apply until the next PosBase/line directive,
					// not just until the new newline)
					column = 0
				} else if d == 0 {
					// the alternative position base is on the current line
					// => column is relative to alternative column
					column = alt.Column + (offset - alt.Offset)
				}
			}
		}
	}
	// TODO(mvdan): move Unlock back under Lock with a defer statement once
	// https://go.dev/issue/38471 is fixed to remove the performance penalty.
	f.mutex.Unlock()
	return
}

func (f *File) position(p Pos, adjusted bool) (pos Position) {
	offset := f.fixOffset(int(p) - f.base)
	pos.Offset = offset
	pos.Filename, pos.Line, pos.Column = f.unpack(offset, adjusted)
	return
}

// PositionFor returns the Position value for the given file position p.
// If p is out of bounds, it is adjusted to match the File.Offset behavior.
// If adjusted is set, the position may be adjusted by position-altering
// //line comments; otherwise those comments are ignored.
// p must be a Pos value in f or NoPos.
func (f *File) PositionFor(p Pos, adjusted bool) (pos Position) {
	if p != NoPos {
		pos = f.position(p, adjusted)
	}
	return
}

// Position returns the Position value for the given file position p.
// If p is out of bounds, it is adjusted to match the File.Offset behavior.
// Calling f.Position(p) is equivalent to calling f.PositionFor(p, true).
func (f *File) Position(p Pos) (pos Position) {
	return f.PositionFor(p, true)
}

// -----------------------------------------------------------------------------
// FileSet

// A FileSet represents a set of source files.
// Methods of file sets are synchronized; multiple goroutines
// may invoke them concurrently.
//
// The byte offsets for each file in a file set are mapped into
// distinct (integer) intervals, one interval [base, base+size]
// per file. [FileSet.Base] represents the first byte in the file, and size
// is the corresponding file size. A [Pos] value is a value in such
// an interval. By determining the interval a [Pos] value belongs
// to, the file, its file base, and thus the byte offset (position)
// the [Pos] value is representing can be computed.
//
// When adding a new file, a file base must be provided. That can
// be any integer value that is past the end of any interval of any
// file already in the file set. For convenience, [FileSet.Base] provides
// such a value, which is simply the end of the Pos interval of the most
// recently added file, plus one. Unless there is a need to extend an
// interval later, using the [FileSet.Base] should be used as argument
// for [FileSet.AddFile].
//
// A [File] may be removed from a FileSet when it is no longer needed.
// This may reduce memory usage in a long-running application.
type FileSet struct {
	mutex sync.RWMutex         // protects the file set
	base  int                  // base offset for the next file
	files []*File              // list of files in the order added to the set
	last  atomic.Pointer[File] // cache of last file looked up
}

// NewFileSet creates a new file set.
func NewFileSet() *FileSet {
	return &FileSet{
		base: 1, // 0 == NoPos
	}
}

// Base returns the minimum base offset that must be provided to
// [FileSet.AddFile] when adding the next file.
func (s *FileSet) Base() int {
	s.mutex.RLock()
	b := s.base
	s.mutex.RUnlock()
	return b
}

// AddFile adds a new file with a given filename, base offset, and file size
// to the file set s and returns the file. Multiple files may have the same
// name. The base offset must not be smaller than the [FileSet.Base], and
// size must not be negative. As a special case, if a negative base is provided,
// the current value of the [FileSet.Base] is used instead.
//
// Adding the file will set the file set's [FileSet.Base] value to base + size + 1
// as the minimum base value for the next file. The following relationship
// exists between a [Pos] value p for a given file offset offs:
//
//	int(p) = base + offs
//
// with offs in the range [0, size] and thus p in the range [base, base+size].
// For convenience, [File.Pos] may be used to create file-specific position
// values from a file offset.
func (s *FileSet) AddFile(filename string, base, size int) *File {
	// Allocate f outside the critical section.
	f := &File{name: filename, size: size, lines: []int{0}}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	if base < 0 {
		base = s.base
	}
	if base < s.base {
		panic(fmt.Sprintf("invalid base %d (should be >= %d)", base, s.base))
	}
	f.base = base
	if size < 0 {
		panic(fmt.Sprintf("invalid size %d (should be >= 0)", size))
	}
	// base >= s.base && size >= 0
	base += size + 1 // +1 because EOF also has a position
	if base < 0 {
		panic("token.Pos offset overflow (> 2G of source code in file set)")
	}
	// add the file to the file set
	s.base = base
	s.files = append(s.files, f)
	s.last.Store(f)
	return f
}

// RemoveFile removes a file from the [FileSet] so that subsequent
// queries for its [Pos] interval yield a negative result.
// This reduces the memory usage of a long-lived [FileSet] that
// encounters an unbounded stream of files.
//
// Removing a file that does not belong to the set has no effect.
func (s *FileSet) RemoveFile(file *File) {
	s.last.CompareAndSwap(file, nil) // clear last file cache

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if i := searchFiles(s.files, file.base); i >= 0 && s.files[i] == file {
		last := &s.files[len(s.files)-1]
		s.files = slices.Delete(s.files, i, i+1)
		*last = nil // don't prolong lifetime when popping last element
	}
}

// Iterate calls f for the files in the file set in the order they were added
// until f returns false.
func (s *FileSet) Iterate(f func(*File) bool) {
	for i := 0; ; i++ {
		var file *File
		s.mutex.RLock()
		if i < len(s.files) {
			file = s.files[i]
		}
		s.mutex.RUnlock()
		if file == nil || !f(file) {
			break
		}
	}
}

func searchFiles(a []*File, x int) int {
	i, found := slices.BinarySearchFunc(a, x, func(a *File, x int) int {
		return cmp.Compare(a.base, x)
	})
	if !found {
		// We want the File containing x, but if we didn't
		// find x then i is the next one.
		i--
	}
	return i
}

func (s *FileSet) file(p Pos) *File {
	// common case: p is in last file.
	if f := s.last.Load(); f != nil && f.base <= int(p) && int(p) <= f.base+f.size {
		return f
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// p is not in last file - search all files
	if i := searchFiles(s.files, int(p)); i >= 0 {
		f := s.files[i]
		// f.base <= int(p) by definition of searchFiles
		if int(p) <= f.base+f.size {
			// Update cache of last file. A race is ok,
			// but an exclusive lock causes heavy contention.
			s.last.Store(f)
			return f
		}
	}
	return nil
}

// File returns the file that contains the position p.
// If no such file is found (for instance for p == [NoPos]),
// the result is nil.
func (s *FileSet) File(p Pos) (f *File) {
	if p != NoPos {
		f = s.file(p)
	}
	return
}

// PositionFor converts a [Pos] p in the fileset into a [Position] value.
// If adjusted is set, the position may be adjusted by position-altering
// //line comments; otherwise those comments are ignored.
// p must be a [Pos] value in s or [NoPos].
func (s *FileSet) PositionFor(p Pos, adjusted bool) (pos Position) {
	if p != NoPos {
		if f := s.file(p); f != nil {
			return f.position(p, adjusted)
		}
	}
	return
}

// Position converts a [Pos] p in the fileset into a Position value.
// Calling s.Position(p) is equivalent to calling s.PositionFor(p, true).
func (s *FileSet) Position(p Pos) (pos Position) {
	return s.PositionFor(p, true)
}

// -----------------------------------------------------------------------------
// Helper functions

func searchInts(a []int, x int) int {
	// This function body is a manually inlined version of:
	//
	//   return sort.Search(len(a), func(i int) bool { return a[i] > x }) - 1
	//
	// With better compiler optimizations, this may not be needed in the
	// future, but at the moment this change improves the go/printer
	// benchmark performance by ~30%. This has a direct impact on the
	// speed of gofmt and thus seems worthwhile (2011-04-29).
	// TODO(gri): Remove this when compilers have caught up.
	i, j := 0, len(a)
	for i < j {
		h := int(uint(i+j) >> 1) // avoid overflow when computing h
		// i ≤ h < j
		if a[h] <= x {
			i = h + 1
		} else {
			j = h
		}
	}
	return i - 1
}
```