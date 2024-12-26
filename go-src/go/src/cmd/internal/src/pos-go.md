Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the `pos.go` file, its use cases, potential pitfalls, and examples. The core idea is to understand how Go tracks source code locations.

2. **Identify Key Structures:**  The code immediately reveals two central structures: `Pos` and `PosBase`. These are the fundamental building blocks for representing source positions.

3. **Analyze `Pos`:**
    * **Fields:** `base *PosBase` and `lico`. This suggests a hierarchical structure where a `Pos` refers to a `PosBase` and contains line/column information within that base.
    * **Purpose:** The comments clearly state `Pos` encodes a source position with line, column, and a base. The "relative" vs. "absolute" distinction is crucial.
    * **Key Methods:**  Go through each method and understand its function. `IsKnown`, `Before`, `After` (ordering), `Filename`, `RelLine`, `RelCol` (relative to the base), `Format`, and `WriteTo` (string representation) stand out.

4. **Analyze `PosBase`:**
    * **Purpose:** The comments indicate `PosBase` represents a starting point for relative positions, typically introduced by file inclusion or `//line` directives.
    * **Fields:**  `pos`, `filename`, `absFilename`, `line`, `col`, `inl`, `fileIndex`. Note how `pos` itself is a `Pos`, creating a self-referential aspect. The fields indicate the base's position *within* another file (or itself), the filenames, the line/column *of the base*, and information related to inlining and file indexing.
    * **Key Methods:** `NewFileBase`, `NewLinePragmaBase`, `NewInliningBase` (constructors), `Pos`, `Filename`, `AbsFilename`, `Line`, `Col`, `InliningIndex` (accessors).

5. **Analyze `lico`:**
    * **Purpose:**  The comment "compact encoding of a LIne and COlumn number" is the key. It's about efficiency.
    * **Structure:** Bit manipulation is evident. The constants (`lineBits`, `colBits`, etc.) reveal how line, column, and statement information are packed into a `uint32`.
    * **Key Methods:**  Accessors like `Line()`, `Col()`, `IsStmt()`, and modifiers like `withIsStmt()`.

6. **Infer Functionality (The "Aha!" Moment):** Based on the structures and methods, the core functionality emerges:
    * **Source Location Tracking:**  The code provides a way to precisely pinpoint locations in source files, even across file inclusions and compiler transformations (like inlining).
    * **Relative Positioning:** The `PosBase` and the "relative" methods (`RelLine`, `RelCol`) strongly suggest the mechanism for handling `#line` directives and inlining. The base provides a context for interpreting the line/column in a `Pos`.
    * **Statement Boundaries:** The `lico` structure's `IsStmt()` and related methods clearly indicate support for tracking statement boundaries for debugging and optimization purposes.

7. **Illustrate with Examples (Go Code):**  Think of typical scenarios:
    * **Basic Position:**  Create a `Pos` within a single file.
    * **`//line` Directive:** Simulate how a `PosBase` is created and how `Pos` uses it to calculate relative positions. This demonstrates the core relative positioning mechanism.
    * **Inlining (Conceptual):**  While the code doesn't have the full inlining logic, explain how `NewInliningBase` would be used to create new `PosBase` instances that point back to the original call site.

8. **Identify Potential Mistakes:** Consider how a user might misuse the API:
    * **Assuming Absolute Positions:**  Forgetting the concept of `PosBase` and relative positions.
    * **Incorrectly Creating `Pos`:**  Not setting the `PosBase` correctly or using the wrong constructor.
    * **Misinterpreting Relative vs. Absolute:** Getting confused about which methods return relative and absolute information.

9. **Command-Line Arguments (If Applicable):**  In this specific case, the code doesn't directly process command-line arguments. Note this and explain *why* it doesn't (it's a data structure and related functions, likely used by other parts of the compiler).

10. **Structure the Answer:** Organize the findings into clear sections: Functionality, Go Language Feature (with examples), Code Inference, Command-line Arguments, and Potential Mistakes. Use headings and bullet points for readability.

11. **Refine and Review:** Read through the explanation to ensure clarity, accuracy, and completeness. Check if the examples are well-explained and if the potential mistakes are relevant. For instance, initially, I might have overlooked the significance of `lico`'s bit packing, but a closer look at the constants and methods would highlight its role in efficiency and storing extra information like statement boundaries.
这段Go语言代码是 `go/src/cmd/internal/src/pos.go` 的一部分，它实现了对源代码位置的编码和管理。其主要功能是：

**1. 表示源代码位置 (Source Position Representation):**

* **`Pos` 结构体:**  核心结构体，用于表示源代码中的一个特定位置。它包含两部分信息：
    * `base *PosBase`: 指向一个 `PosBase` 结构体的指针。`PosBase` 定义了位置的“基准”，例如文件的起始位置或 `//line` 指令的位置。
    * `lico`:  一个 `lico` 类型的字段，紧凑地编码了相对于 `PosBase` 的行号和列号。

* **`lico` 类型:** 使用一个 `uint32` 来紧凑地存储行号、列号以及是否为语句起始位置等信息，通过位运算进行编码和解码，节省空间。

**2. 管理位置基准 (Position Base Management):**

* **`PosBase` 结构体:**  用于定义一个位置的基准。它包含：
    * `pos Pos`:  定义了 `PosBase` 本身在源文件中的位置。
    * `filename string`:  用于打开源文件的文件名（相对路径）。
    * `absFilename string`: 源文件的绝对路径，用于生成 PC-Line 表等调试信息。
    * `line, col uint`: 相对于此 `PosBase` 的起始行号和列号。
    * `inl int`:  内联索引，用于跟踪内联函数的原始位置。
    * `fileIndex int`:  `absFilename` 在 `PosTable` 中的索引。

* **`NewFileBase` 函数:**  创建一个新的 `PosBase`，通常用于表示一个文件的起始位置。
* **`NewLinePragmaBase` 函数:**  创建一个新的 `PosBase`，用于处理 `//line` 或 `/*line*/` 指令，允许修改后续代码的报告位置。
* **`NewInliningBase` 函数:**  创建一个基于现有 `PosBase` 的新 `PosBase`，用于记录内联函数调用的位置信息。

**3. 位置信息的访问和操作:**

* **`IsKnown()` 方法:**  判断一个 `Pos` 是否已知（有有效的 `PosBase` 或非零行号）。
* **`Before()` 和 `After()` 方法:**  比较两个 `Pos` 的先后顺序，首先按文件名比较，然后按行号和列号比较。
* **`LineNumber()` 和 `LineNumberHTML()` 方法:**  获取 `Pos` 的行号，`LineNumberHTML()` 还会根据是否为语句起始位置添加 HTML 标签。
* **`Filename()` 方法:**  获取 `Pos` 所在的文件名（通过 `PosBase` 获取）。
* **`RelFilename()`, `RelLine()`, `RelCol()` 方法:**  获取相对于 `Pos` 的 `PosBase` 的文件名、行号和列号。
* **`AbsFilename()` 和 `FileIndex()` 方法:**  获取 `Pos` 对应的绝对文件名和文件索引。
* **`String()` 和 `Format()` 方法:**  将 `Pos` 格式化为字符串，例如 "filename:line" 或 "filename:line:column"。
* **`WriteTo()` 方法:**  将 `Pos` 的格式化输出写入 `io.Writer`。

**推理 Go 语言功能：源代码位置跟踪和调试信息生成**

这段代码是 Go 语言编译器或相关工具链用于跟踪源代码位置的关键组成部分。它主要用于：

* **错误和警告报告:** 当编译器、链接器或其他工具遇到错误或警告时，可以使用 `Pos` 信息准确地指出问题发生的源代码位置，方便开发者定位和修复。
* **调试信息生成:**  生成调试信息（例如 DWARF），需要记录程序执行过程中指令与源代码的对应关系。`Pos` 结构体以及 `PosBase` 提供的绝对文件名和行号信息是生成 PC-Line 表等调试信息的关键。
* **代码内联 (Inlining):**  在代码内联优化过程中，需要记录被内联函数的原始位置信息，以便在调试时能够回溯到原始代码。`NewInliningBase` 和 `InliningIndex()` 就是为此目的设计的。
* **`//line` 指令处理:**  Go 语言支持 `//line filename:line:col` 这样的指令，用于改变后续代码的报告位置。`NewLinePragmaBase` 就是用于处理这类指令的。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"go/src/cmd/internal/src"
)

func main() {
	// 创建一个文件起始位置的 PosBase
	base := src.NewFileBase("example.go", "/path/to/example.go")

	// 创建一个位于文件第一行，第10列的 Pos
	pos1 := src.MakePos(base, 1, 10)
	fmt.Println(pos1.String()) // 输出: example.go:1:10

	// 创建一个基于 line 指令的 PosBase
	lineBase := src.NewLinePragmaBase(pos1, "another.go", "/path/to/another.go", 5, 20)

	// 创建一个基于 lineBase 的 Pos
	pos2 := src.MakePos(lineBase, 10, 30) // 注意这里的 10, 30 是相对于 another.go 的绝对位置
	fmt.Println(pos2.String()) // 输出: another.go:5:20[example.go:1:10]  显示了相对位置和原始位置

	// 创建一个未知的 Pos
	unknownPos := src.NoPos
	fmt.Println(unknownPos.String()) // 输出: <unknown line number>

	// 比较两个 Pos
	fmt.Println(pos1.Before(pos2)) // 输出: true (因为 example.go 在 another.go 之前)
}
```

**假设的输入与输出:**

上面的代码示例中，我们假设创建了一个名为 "example.go" 的文件，并在其中使用了 `//line` 指令。

* **输入:**  `src.NewFileBase("example.go", "/path/to/example.go")`, `src.MakePos(base, 1, 10)`, `src.NewLinePragmaBase(pos1, "another.go", "/path/to/another.go", 5, 20)`, `src.MakePos(lineBase, 10, 30)`, `src.NoPos`.
* **输出:**
    ```
    example.go:1:10
    another.go:5:20[example.go:1:10]
    <unknown line number>
    true
    ```

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。它是一个内部库，负责表示和管理源代码位置信息。命令行参数的处理通常发生在 Go 编译器的前端（例如 `go/src/cmd/compile/internal/syntax`）或相关工具的入口点。这些工具会解析命令行参数，并根据需要创建和使用 `src.Pos` 和 `src.PosBase` 来跟踪源文件位置。

例如，编译器在解析源文件时，会读取文件内容，并为每个 token 或 AST 节点关联一个 `src.Pos`，该 `Pos` 的 `PosBase` 通常是使用 `NewFileBase` 创建的。当遇到 `//line` 指令时，编译器会使用 `NewLinePragmaBase` 创建一个新的 `PosBase`，并更新后续代码的关联位置信息。

**使用者易犯错的点:**

* **混淆绝对位置和相对位置:**  初学者可能会混淆 `Pos` 结构体中的绝对行列号 (`lico`) 和相对于 `PosBase` 的行列号 (`PosBase` 中的 `line` 和 `col`)。需要理解 `PosBase` 的作用是定义一个相对位置的起始点。

* **错误地创建 `PosBase`:**  不理解 `NewFileBase` 和 `NewLinePragmaBase` 的使用场景，例如在处理 `//line` 指令时仍然使用 `NewFileBase`，会导致位置信息错误。

* **假设所有位置都有有效的 `PosBase`:**  `NoPos` 表示未知位置，使用者在处理 `Pos` 时需要检查 `IsKnown()` 的返回值，避免在 `base` 为 `nil` 时访问其成员。

* **忽略 `lico` 的紧凑编码:**  直接操作 `lico` 的位字段可能会出错，应该使用其提供的 `Line()`, `Col()`, `IsStmt()` 等方法进行访问和修改。

总而言之，`go/src/cmd/internal/src/pos.go` 提供了一套精巧的机制来表示和管理 Go 源代码的位置信息，这对于编译器的错误报告、调试信息的生成以及代码内联等优化至关重要。理解 `Pos` 和 `PosBase` 的关系以及 `lico` 的编码方式是正确使用和理解这段代码的关键。

Prompt: 
```
这是路径为go/src/cmd/internal/src/pos.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements the encoding of source positions.

package src

import (
	"bytes"
	"fmt"
	"io"
)

// A Pos encodes a source position consisting of a (line, column) number pair
// and a position base. A zero Pos is a ready to use "unknown" position (nil
// position base and zero line number).
//
// The (line, column) values refer to a position in a file independent of any
// position base ("absolute" file position).
//
// The position base is used to determine the "relative" position, that is the
// filename and line number relative to the position base. If the base refers
// to the current file, there is no difference between absolute and relative
// positions. If it refers to a //line directive, a relative position is relative
// to that directive. A position base in turn contains the position at which it
// was introduced in the current file.
type Pos struct {
	base *PosBase
	lico
}

// NoPos is a valid unknown position.
var NoPos Pos

// MakePos creates a new Pos value with the given base, and (file-absolute)
// line and column.
func MakePos(base *PosBase, line, col uint) Pos {
	return Pos{base, makeLico(line, col)}
}

// IsKnown reports whether the position p is known.
// A position is known if it either has a non-nil
// position base, or a non-zero line number.
func (p Pos) IsKnown() bool {
	return p.base != nil || p.Line() != 0
}

// Before reports whether the position p comes before q in the source.
// For positions in different files, ordering is by filename.
func (p Pos) Before(q Pos) bool {
	n, m := p.Filename(), q.Filename()
	return n < m || n == m && p.lico < q.lico
}

// After reports whether the position p comes after q in the source.
// For positions in different files, ordering is by filename.
func (p Pos) After(q Pos) bool {
	n, m := p.Filename(), q.Filename()
	return n > m || n == m && p.lico > q.lico
}

func (p Pos) LineNumber() string {
	if !p.IsKnown() {
		return "?"
	}
	return p.lico.lineNumber()
}

func (p Pos) LineNumberHTML() string {
	if !p.IsKnown() {
		return "?"
	}
	return p.lico.lineNumberHTML()
}

// Filename returns the name of the actual file containing this position.
func (p Pos) Filename() string { return p.base.Pos().RelFilename() }

// Base returns the position base.
func (p Pos) Base() *PosBase { return p.base }

// SetBase sets the position base.
func (p *Pos) SetBase(base *PosBase) { p.base = base }

// RelFilename returns the filename recorded with the position's base.
func (p Pos) RelFilename() string { return p.base.Filename() }

// RelLine returns the line number relative to the position's base.
func (p Pos) RelLine() uint {
	b := p.base
	if b.Line() == 0 {
		// base line is unknown => relative line is unknown
		return 0
	}
	return b.Line() + (p.Line() - b.Pos().Line())
}

// RelCol returns the column number relative to the position's base.
func (p Pos) RelCol() uint {
	b := p.base
	if b.Col() == 0 {
		// base column is unknown => relative column is unknown
		// (the current specification for line directives requires
		// this to apply until the next PosBase/line directive,
		// not just until the new newline)
		return 0
	}
	if p.Line() == b.Pos().Line() {
		// p on same line as p's base => column is relative to p's base
		return b.Col() + (p.Col() - b.Pos().Col())
	}
	return p.Col()
}

// AbsFilename() returns the absolute filename recorded with the position's base.
func (p Pos) AbsFilename() string { return p.base.AbsFilename() }

// FileIndex returns the file index of the position's base's absolute
// filename within the PosTable that it was registered.
func (p Pos) FileIndex() int { return p.base.FileIndex() }

func (p Pos) String() string {
	return p.Format(true, true)
}

// Format formats a position as "filename:line" or "filename:line:column",
// controlled by the showCol flag and if the column is known (!= 0).
// For positions relative to line directives, the original position is
// shown as well, as in "filename:line[origfile:origline:origcolumn]" if
// showOrig is set.
func (p Pos) Format(showCol, showOrig bool) string {
	buf := new(bytes.Buffer)
	p.WriteTo(buf, showCol, showOrig)
	return buf.String()
}

// WriteTo a position to w, formatted as Format does.
func (p Pos) WriteTo(w io.Writer, showCol, showOrig bool) {
	if !p.IsKnown() {
		io.WriteString(w, "<unknown line number>")
		return
	}

	if b := p.base; b == b.Pos().base {
		// base is file base (incl. nil)
		format(w, p.Filename(), p.Line(), p.Col(), showCol)
		return
	}

	// base is relative
	// Print the column only for the original position since the
	// relative position's column information may be bogus (it's
	// typically generated code and we can't say much about the
	// original source at that point but for the file:line info
	// that's provided via a line directive).
	// TODO(gri) This may not be true if we have an inlining base.
	// We may want to differentiate at some point.
	format(w, p.RelFilename(), p.RelLine(), p.RelCol(), showCol)
	if showOrig {
		io.WriteString(w, "[")
		format(w, p.Filename(), p.Line(), p.Col(), showCol)
		io.WriteString(w, "]")
	}
}

// format formats a (filename, line, col) tuple as "filename:line" (showCol
// is false or col == 0) or "filename:line:column" (showCol is true and col != 0).
func format(w io.Writer, filename string, line, col uint, showCol bool) {
	io.WriteString(w, filename)
	io.WriteString(w, ":")
	fmt.Fprint(w, line)
	// col == 0 and col == colMax are interpreted as unknown column values
	if showCol && 0 < col && col < colMax {
		io.WriteString(w, ":")
		fmt.Fprint(w, col)
	}
}

// formatstr wraps format to return a string.
func formatstr(filename string, line, col uint, showCol bool) string {
	buf := new(bytes.Buffer)
	format(buf, filename, line, col, showCol)
	return buf.String()
}

// ----------------------------------------------------------------------------
// PosBase

// A PosBase encodes a filename and base position.
// Typically, each file and line directive introduce a PosBase.
type PosBase struct {
	pos         Pos    // position at which the relative position is (line, col)
	filename    string // file name used to open source file, for error messages
	absFilename string // absolute file name, for PC-Line tables
	line, col   uint   // relative line, column number at pos
	inl         int    // inlining index (see cmd/internal/obj/inl.go)
	fileIndex   int    // index of absFilename within PosTable.FileTable
}

// NewFileBase returns a new *PosBase for a file with the given (relative and
// absolute) filenames.
func NewFileBase(filename, absFilename string) *PosBase {
	base := &PosBase{
		filename:    filename,
		absFilename: absFilename,
		line:        1,
		col:         1,
		inl:         -1,
		fileIndex:   -1,
	}
	base.pos = MakePos(base, 1, 1)
	return base
}

// NewLinePragmaBase returns a new *PosBase for a line directive of the form
//
//	//line filename:line:col
//	/*line filename:line:col*/
//
// at position pos.
func NewLinePragmaBase(pos Pos, filename, absFilename string, line, col uint) *PosBase {
	return &PosBase{pos, filename, absFilename, line, col, -1, -1}
}

// NewInliningBase returns a copy of the orig PosBase with the given inlining
// index. If orig == nil, NewInliningBase panics.
func NewInliningBase(orig *PosBase, inlTreeIndex int) *PosBase {
	if orig == nil {
		panic("no old PosBase")
	}
	base := *orig
	base.inl = inlTreeIndex
	base.fileIndex = -1
	if orig == orig.pos.base {
		base.pos.base = &base
	}
	return &base
}

var noPos Pos

// Pos returns the position at which base is located.
// If b == nil, the result is the zero position.
func (b *PosBase) Pos() *Pos {
	if b != nil {
		return &b.pos
	}
	return &noPos
}

// Filename returns the filename recorded with the base.
// If b == nil, the result is the empty string.
func (b *PosBase) Filename() string {
	if b != nil {
		return b.filename
	}
	return ""
}

// AbsFilename returns the absolute filename recorded with the base.
// If b == nil, the result is the empty string.
func (b *PosBase) AbsFilename() string {
	if b != nil {
		return b.absFilename
	}
	return ""
}

// FileSymPrefix is the linker symbol prefix that used to be used for
// linker pseudo-symbols representing file names.
const FileSymPrefix = "gofile.."

// FileIndex returns the index of the base's absolute filename within
// its PosTable's FileTable. It panics if it hasn't been registered
// with a PosTable. If b == nil, the result is -1.
func (b *PosBase) FileIndex() int {
	if b != nil {
		if b.fileIndex < 0 {
			panic("PosBase has no file index")
		}
		return b.fileIndex
	}
	return -1
}

// Line returns the line number recorded with the base.
// If b == nil, the result is 0.
func (b *PosBase) Line() uint {
	if b != nil {
		return b.line
	}
	return 0
}

// Col returns the column number recorded with the base.
// If b == nil, the result is 0.
func (b *PosBase) Col() uint {
	if b != nil {
		return b.col
	}
	return 0
}

// InliningIndex returns the index into the global inlining
// tree recorded with the base. If b == nil or the base has
// not been inlined, the result is < 0.
func (b *PosBase) InliningIndex() int {
	if b != nil {
		return b.inl
	}
	return -1
}

// ----------------------------------------------------------------------------
// lico

// A lico is a compact encoding of a LIne and COlumn number.
type lico uint32

// Layout constants: 20 bits for line, 8 bits for column, 2 for isStmt, 2 for pro/epilogue
// (If this is too tight, we can either make lico 64b wide,
// or we can introduce a tiered encoding where we remove column
// information as line numbers grow bigger; similar to what gcc
// does.)
// The bitfield order is chosen to make IsStmt be the least significant
// part of a position; its use is to communicate statement edges through
// instruction scrambling in code generation, not to impose an order.
// TODO: Prologue and epilogue are perhaps better handled as pseudo-ops for the assembler,
// because they have almost no interaction with other uses of the position.
const (
	lineBits, lineMax     = 20, 1<<lineBits - 2
	bogusLine             = 1 // Used to disrupt infinite loops to prevent debugger looping
	isStmtBits, isStmtMax = 2, 1<<isStmtBits - 1
	xlogueBits, xlogueMax = 2, 1<<xlogueBits - 1
	colBits, colMax       = 32 - lineBits - xlogueBits - isStmtBits, 1<<colBits - 1

	isStmtShift = 0
	isStmtMask  = isStmtMax << isStmtShift
	xlogueShift = isStmtBits + isStmtShift
	xlogueMask  = xlogueMax << xlogueShift
	colShift    = xlogueBits + xlogueShift
	lineShift   = colBits + colShift
)
const (
	// It is expected that the front end or a phase in SSA will usually generate positions tagged with
	// PosDefaultStmt, but note statement boundaries with PosIsStmt.  Simple statements will have a single
	// boundary; for loops with initialization may have one for their entry and one for their back edge
	// (this depends on exactly how the loop is compiled; the intent is to provide a good experience to a
	// user debugging a program; the goal is that a breakpoint set on the loop line fires both on entry
	// and on iteration).  Proper treatment of non-gofmt input with multiple simple statements on a single
	// line is TBD.
	//
	// Optimizing compilation will move instructions around, and some of these will become known-bad as
	// step targets for debugging purposes (examples: register spills and reloads; code generated into
	// the entry block; invariant code hoisted out of loops) but those instructions will still have interesting
	// positions for profiling purposes. To reflect this these positions will be changed to PosNotStmt.
	//
	// When the optimizer removes an instruction marked PosIsStmt; it should attempt to find a nearby
	// instruction with the same line marked PosDefaultStmt to be the new statement boundary.  I.e., the
	// optimizer should make a best-effort to conserve statement boundary positions, and might be enhanced
	// to note when a statement boundary is not conserved.
	//
	// Code cloning, e.g. loop unrolling or loop unswitching, is an exception to the conservation rule
	// because a user running a debugger would expect to see breakpoints active in the copies of the code.
	//
	// In non-optimizing compilation there is still a role for PosNotStmt because of code generation
	// into the entry block.  PosIsStmt statement positions should be conserved.
	//
	// When code generation occurs any remaining default-marked positions are replaced with not-statement
	// positions.
	//
	PosDefaultStmt uint = iota // Default; position is not a statement boundary, but might be if optimization removes the designated statement boundary
	PosIsStmt                  // Position is a statement boundary; if optimization removes the corresponding instruction, it should attempt to find a new instruction to be the boundary.
	PosNotStmt                 // Position should not be a statement boundary, but line should be preserved for profiling and low-level debugging purposes.
)

type PosXlogue uint

const (
	PosDefaultLogue PosXlogue = iota
	PosPrologueEnd
	PosEpilogueBegin
)

func makeLicoRaw(line, col uint) lico {
	return lico(line<<lineShift | col<<colShift)
}

// This is a not-position that will not be elided.
// Depending on the debugger (gdb or delve) it may or may not be displayed.
func makeBogusLico() lico {
	return makeLicoRaw(bogusLine, 0).withIsStmt()
}

func makeLico(line, col uint) lico {
	if line >= lineMax {
		// cannot represent line, use max. line so we have some information
		line = lineMax
		// Drop column information if line number saturates.
		// Ensures line+col is monotonic. See issue 51193.
		col = 0
	}
	if col > colMax {
		// cannot represent column, use max. column so we have some information
		col = colMax
	}
	// default is not-sure-if-statement
	return makeLicoRaw(line, col)
}

func (x lico) Line() uint           { return uint(x) >> lineShift }
func (x lico) SameLine(y lico) bool { return 0 == (x^y)&^lico(1<<lineShift-1) }
func (x lico) Col() uint            { return uint(x) >> colShift & colMax }
func (x lico) IsStmt() uint {
	if x == 0 {
		return PosNotStmt
	}
	return uint(x) >> isStmtShift & isStmtMax
}
func (x lico) Xlogue() PosXlogue {
	return PosXlogue(uint(x) >> xlogueShift & xlogueMax)
}

// withNotStmt returns a lico for the same location, but not a statement
func (x lico) withNotStmt() lico {
	return x.withStmt(PosNotStmt)
}

// withDefaultStmt returns a lico for the same location, with default isStmt
func (x lico) withDefaultStmt() lico {
	return x.withStmt(PosDefaultStmt)
}

// withIsStmt returns a lico for the same location, tagged as definitely a statement
func (x lico) withIsStmt() lico {
	return x.withStmt(PosIsStmt)
}

// withXlogue attaches a prologue/epilogue attribute to a lico
func (x lico) withXlogue(xlogue PosXlogue) lico {
	if x == 0 {
		if xlogue == 0 {
			return x
		}
		// Normalize 0 to "not a statement"
		x = lico(PosNotStmt << isStmtShift)
	}
	return lico(uint(x) & ^uint(xlogueMax<<xlogueShift) | (uint(xlogue) << xlogueShift))
}

// withStmt returns a lico for the same location with specified is_stmt attribute
func (x lico) withStmt(stmt uint) lico {
	if x == 0 {
		return lico(0)
	}
	return lico(uint(x) & ^uint(isStmtMax<<isStmtShift) | (stmt << isStmtShift))
}

func (x lico) lineNumber() string {
	return fmt.Sprintf("%d", x.Line())
}

func (x lico) lineNumberHTML() string {
	if x.IsStmt() == PosDefaultStmt {
		return fmt.Sprintf("%d", x.Line())
	}
	style, pfx := "b", "+"
	if x.IsStmt() == PosNotStmt {
		style = "s" // /strike not supported in HTML5
		pfx = ""
	}
	return fmt.Sprintf("<%s>%s%d</%s>", style, pfx, x.Line(), style)
}

func (x lico) atColumn1() lico {
	return makeLico(x.Line(), 1).withIsStmt()
}

"""



```