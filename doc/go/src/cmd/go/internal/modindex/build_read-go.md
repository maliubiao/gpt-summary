Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The initial request asks for the functionality of the provided Go code, specifically the `build_read.go` file within the `modindex` package. The request also probes for its broader purpose within Go, illustrative examples, command-line interaction, and common pitfalls.

2. **Initial Skim and Key Structures:**  A quick scan reveals several important components:
    * `importReader`:  This struct clearly deals with reading input, likely Go source code. It has fields like `b` (buffer), `buf`, `peek`, `err`, and `pos` which are typical for buffered readers.
    * Helper functions:  `newImportReader`, `isIdent`, `readByte`, `peekByte`, `nextByte`, `readKeyword`, `readIdent`, `readString`, `readImport`, `findEmbed`, `readComments`, `readGoInfo`, `parseGoEmbed`. The naming suggests specific parsing tasks.
    * `fileInfo` (though its full definition isn't in this snippet, it's clearly used to store information about a Go file).
    * Constants like `bom` and `goEmbed`.
    * Error variables `errSyntax` and `errNUL`.

3. **Focus on the Core Functionality - Reading and Parsing:** The file name `build_read.go` and the presence of `importReader` strongly suggest that the primary function is to read and parse Go source code, specifically focusing on imports and possibly other build-related information.

4. **Analyze Key Functions:**

    * **`importReader` methods (`readByte`, `peekByte`, `nextByte`):** These are standard building blocks for any custom reader. They handle byte-level input, buffering, peeking ahead, and managing position. The skipping of spaces and comments in `peekByte` is a common parsing technique.
    * **`readKeyword`, `readIdent`, `readString`, `readImport`:** These functions indicate a basic Go syntax parser, focusing on keywords, identifiers, and string literals, particularly in the context of import declarations.
    * **`readComments`:**  This is straightforward – extracting initial comments.
    * **`readGoInfo`:** This seems to be the central function. It uses `importReader` to process a Go file. The steps are revealing:
        * Read `package` declaration.
        * Read `import` declarations (handling both single and grouped imports).
        * Store the header (package and import block).
        * *Conditional Parsing:* If `info.fset` is provided (implying a desire for deeper analysis), it uses the `go/parser` package to parse the header. This extracts import paths and comments associated with imports.
        * *Directive Extraction:* It looks for `//go:` directives in the comments.
        * *`//go:embed` Handling:* If the file imports "embed", it searches for `//go:embed` directives in the *rest* of the file.
    * **`findEmbed` and `parseGoEmbed`:** These are dedicated to finding and parsing the `//go:embed` directives, extracting the file patterns.

5. **Infer the Broader Go Functionality:** The presence of `//go:embed` and the focus on imports strongly suggest this code is related to the **Go Modules feature**, specifically the part that deals with understanding the dependencies and embedded files of a module. The `modindex` package name further reinforces this idea. It likely helps the `go` command build and manage modules efficiently by indexing this information.

6. **Construct Examples (Mental or Actual):** Think of common Go code snippets involving imports and `//go:embed`:

    ```go
    package main

    import (
        "fmt"
        "os"
        _ "unsafe"
        "embed"
    )

    //go:embed version.txt
    var version string

    func main() {
        fmt.Println("Hello, world!")
        fmt.Println("Version:", version)
    }
    ```

7. **Relate to Command-Line Parameters:**  Consider how the `go` command might use this. Commands like `go build`, `go run`, `go list -m`, and `go mod tidy` all need to understand module dependencies and embedded files. The code likely doesn't directly process command-line arguments, but it *supports* those commands by providing the necessary information.

8. **Identify Potential Mistakes:** Think about common errors developers make with modules and `//go:embed`:

    * Incorrectly formatted `//go:embed` directives (spaces, quotes).
    * Placing `//go:embed` directives outside of the variable declaration they are associated with.
    * Issues with the file paths specified in `//go:embed`.

9. **Structure the Answer:** Organize the findings into logical sections as requested:
    * Functionality summary.
    * Explanation of the broader Go feature (Go Modules and `//go:embed`).
    * Code examples with inputs and outputs (demonstrating `readGoInfo` and `parseGoEmbed`).
    * Explanation of command-line parameter interaction (indirectly supports `go` commands).
    * Common mistakes (focus on `//go:embed` usage).

10. **Refine and Review:**  Read through the generated answer, ensuring clarity, accuracy, and completeness. Double-check the code examples and the explanations of the Go features. For example, initially, I might just say "it parses Go code". But refining that to "specifically focusing on imports, `//go:embed` directives, and other build-related information" is more precise. Similarly, initially I might forget to mention directives and then add that in.

This iterative process of skimming, focusing, analyzing, inferring, and refining helps to generate a comprehensive and accurate answer to the initial request.
这段代码是 Go 语言 `cmd/go` 工具中 `internal/modindex` 包的一部分，主要功能是 **读取 Go 源代码文件，解析其中的 import 声明、`//go:` 指令（directives）以及 `//go:embed` 指令，用于构建模块索引。**  它是一个轻量级的 Go 语法解析器，专注于提取构建工具所需的信息，而不是进行完整的语法分析。

让我们分解一下它的具体功能：

**1. 读取 Go 源代码文件到一定程度:**

* 它使用 `newImportReader` 创建一个自定义的读取器 `importReader`，该读取器基于 `bufio.Reader`，并处理 UTF-8 BOM。
* `readGoInfo` 是核心函数，它接收一个 `io.Reader` 和一个 `fileInfo` 结构体指针。
* 它会读取文件的前部分，直到遇到第一个非 `import` 声明为止。 这意味着它会读取 `package` 声明和所有的 `import` 声明。

**2. 解析 `package` 声明:**

* `readKeyword("package")` 和 `readIdent()` 用于读取并验证 `package` 关键字和包名。

**3. 解析 `import` 声明:**

* 它能处理单行 `import` 和带括号的 `import` 组。
* `readImport()` 函数用于读取单个 `import` 声明，它可以识别带别名的导入（例如 `alias "path"`）和 `.` 导入。

**4. 提取 `//go:` 指令 (directives):**

* 在解析 `import` 声明之后，`readGoInfo` 会查找以 `//go:` 开头的注释，并将它们存储在 `info.directives` 中。 这些指令通常用于指示构建工具执行特定的操作，例如设置构建约束。

**5. 提取 `//go:embed` 指令:**

* 如果文件中导入了 `embed` 包，`readGoInfo` 会继续扫描文件的剩余部分，查找 `//go:embed` 注释。
* `findEmbed` 函数负责查找 `//go:embed` 注释。
* `parseGoEmbed` 函数解析 `//go:embed` 注释后面的参数，提取出需要嵌入的文件或目录的 glob 模式。

**6. 可选的完整语法解析:**

* 如果传递给 `readGoInfo` 的 `fileInfo` 结构体的 `fset` 字段非空，则会使用 `go/parser` 包进行更深入的语法分析。
* 这将解析整个文件头（package 和 import 声明部分），并将解析结果（`ast.File`）、解析错误、导入路径信息和 `//go:embed` 信息存储在 `fileInfo` 结构体中。

**可以推理出它是 Go 模块功能中用于快速提取依赖和嵌入资源信息的实现。**  在构建 Go 模块时，`go` 命令需要快速确定模块的依赖关系以及需要嵌入的静态资源，而无需进行完整的 Go 语法分析。 `modindex` 包提供的功能正是为了满足这个需求。

**Go 代码举例说明:**

假设我们有以下 Go 代码文件 `example.go`:

```go
package main

import (
	"fmt"
	"os"

	_ "unsafe" // 用于演示忽略的导入

	"embed"
)

//go:embed version.txt
var version string

//go:embed assets/*
var assets embed.FS

//go:directive some_directive // 这是一个指令，但 go/build 包可能不会识别

func main() {
	fmt.Println("Hello, world!")
	fmt.Println("Version:", version)
	// 访问嵌入的资源
	content, _ := assets.ReadFile("assets/data.txt")
	fmt.Println("Data:", string(content))
}
```

以及一个 `version.txt` 文件：

```
v1.0.0
```

和一个 `assets/data.txt` 文件：

```
This is some data.
```

**假设的输入与输出:**

如果我们使用 `readGoInfo` 函数处理 `example.go` 文件，并提供一个空的 `fileInfo` 结构体，预期的输出（存储在 `fileInfo` 中）将包含：

* **`info.header`:** 包含 `package main\n\nimport (\n\t"fmt"\n\tos.Stderr\n\n\t_ "unsafe" // 用于演示忽略的导入\n\n\t"embed"\n)` 这样的字节切片。
* **`info.directives`:** 包含一个 `build.Directive` 结构体，其 `Text` 字段为 `//go:directive some_directive`。
* **`info.embeds`:** 包含两个 `fileEmbed` 结构体，分别对应 `//go:embed version.txt` 和 `//go:embed assets/*`， 包含路径和位置信息。

**如果 `info.fset` 非空，则还会包含:**

* **`info.parsed`:**  一个 `*ast.File`，表示 Go 代码的抽象语法树（仅包含 package 和 import 部分）。
* **`info.parseErr`:**  解析过程中遇到的错误（如果存在）。
* **`info.imports`:** 一个 `fileImport` 切片，包含每个导入的路径和位置信息，例如：
    * `{"fmt", ...}`
    * `{"os", ...}`
    * `{"unsafe", ...}`
    * `{"embed", ...}`

**代码推理:**

`readGoInfo` 函数的核心逻辑是逐步读取文件，识别关键字和结构，并提取相关信息。 例如，当遇到 `import` 关键字时，它会调用 `readImport` 来解析导入路径。 当遇到 `//` 开头的行时，它会检查是否是 `//go:` 或 `//go:embed` 指令。

`parseGoEmbed` 函数使用状态机或简单的字符串处理来解析 `//go:embed` 后面的参数，处理带引号和不带引号的路径模式。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。 它的作用是作为 `go` 命令内部的一个模块，为其他处理命令行参数的组件提供数据。 例如，当执行 `go build` 或 `go mod tidy` 时，这些命令会调用 `modindex` 包中的函数来获取模块的依赖关系和嵌入资源信息，从而决定需要编译哪些包或需要下载哪些模块。

**使用者易犯错的点 (与 `//go:embed` 相关):**

1. **`//go:embed` 注释的位置错误:**  `//go:embed` 注释必须紧跟在要嵌入资源的 `var` 声明之前，中间不能有空行或其他注释。

   ```go
   // 错误示例
   //go:embed file.txt
   var content string
   ```

   ```go
   // 正确示例
   //go:embed file.txt
   var content string
   ```

2. **`//go:embed` 的语法错误:**  `//go:embed` 后面需要跟一个或多个空格分隔的模式，模式可以是未加引号的路径，也可以是双引号或反引号括起来的字符串。  模式中可以使用通配符 `*`。

   ```go
   // 错误示例
   //go:embed "file.txt  anotherfile.txt" // 应该用空格分隔
   var contents embed.FS

   // 错误示例
   //go:embed file*.txt // 正确，可以使用通配符
   var files embed.FS
   ```

3. **嵌入的资源不存在:**  如果在 `//go:embed` 中指定的路径不存在，编译时会报错。

4. **嵌入的资源类型与变量类型不匹配:** 如果尝试将多个文件或目录嵌入到 `string` 类型的变量中，或者将单个文件嵌入到 `embed.FS` 类型的变量中，会导致编译错误。

   ```go
   // 错误示例
   //go:embed *.txt
   var content string // 无法将多个文件嵌入到 string
   ```

总而言之，这段代码是 Go 模块系统中用于高效提取 Go 源代码中关键信息的底层实现，特别关注于 `import` 声明、`//go:` 指令以及 `//go:embed` 指令，为 `go` 命令的构建和模块管理功能提供了基础数据。

### 提示词
```
这是路径为go/src/cmd/go/internal/modindex/build_read.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is a lightly modified copy go/build/read.go with unused parts
// removed.

package modindex

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type importReader struct {
	b    *bufio.Reader
	buf  []byte
	peek byte
	err  error
	eof  bool
	nerr int
	pos  token.Position
}

var bom = []byte{0xef, 0xbb, 0xbf}

func newImportReader(name string, r io.Reader) *importReader {
	b := bufio.NewReader(r)
	// Remove leading UTF-8 BOM.
	// Per https://golang.org/ref/spec#Source_code_representation:
	// a compiler may ignore a UTF-8-encoded byte order mark (U+FEFF)
	// if it is the first Unicode code point in the source text.
	if leadingBytes, err := b.Peek(3); err == nil && bytes.Equal(leadingBytes, bom) {
		b.Discard(3)
	}
	return &importReader{
		b: b,
		pos: token.Position{
			Filename: name,
			Line:     1,
			Column:   1,
		},
	}
}

func isIdent(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_' || c >= utf8.RuneSelf
}

var (
	errSyntax = errors.New("syntax error")
	errNUL    = errors.New("unexpected NUL in input")
)

// syntaxError records a syntax error, but only if an I/O error has not already been recorded.
func (r *importReader) syntaxError() {
	if r.err == nil {
		r.err = errSyntax
	}
}

// readByte reads the next byte from the input, saves it in buf, and returns it.
// If an error occurs, readByte records the error in r.err and returns 0.
func (r *importReader) readByte() byte {
	c, err := r.b.ReadByte()
	if err == nil {
		r.buf = append(r.buf, c)
		if c == 0 {
			err = errNUL
		}
	}
	if err != nil {
		if err == io.EOF {
			r.eof = true
		} else if r.err == nil {
			r.err = err
		}
		c = 0
	}
	return c
}

// readByteNoBuf is like readByte but doesn't buffer the byte.
// It exhausts r.buf before reading from r.b.
func (r *importReader) readByteNoBuf() byte {
	var c byte
	var err error
	if len(r.buf) > 0 {
		c = r.buf[0]
		r.buf = r.buf[1:]
	} else {
		c, err = r.b.ReadByte()
		if err == nil && c == 0 {
			err = errNUL
		}
	}

	if err != nil {
		if err == io.EOF {
			r.eof = true
		} else if r.err == nil {
			r.err = err
		}
		return 0
	}
	r.pos.Offset++
	if c == '\n' {
		r.pos.Line++
		r.pos.Column = 1
	} else {
		r.pos.Column++
	}
	return c
}

// peekByte returns the next byte from the input reader but does not advance beyond it.
// If skipSpace is set, peekByte skips leading spaces and comments.
func (r *importReader) peekByte(skipSpace bool) byte {
	if r.err != nil {
		if r.nerr++; r.nerr > 10000 {
			panic("go/build: import reader looping")
		}
		return 0
	}

	// Use r.peek as first input byte.
	// Don't just return r.peek here: it might have been left by peekByte(false)
	// and this might be peekByte(true).
	c := r.peek
	if c == 0 {
		c = r.readByte()
	}
	for r.err == nil && !r.eof {
		if skipSpace {
			// For the purposes of this reader, semicolons are never necessary to
			// understand the input and are treated as spaces.
			switch c {
			case ' ', '\f', '\t', '\r', '\n', ';':
				c = r.readByte()
				continue

			case '/':
				c = r.readByte()
				if c == '/' {
					for c != '\n' && r.err == nil && !r.eof {
						c = r.readByte()
					}
				} else if c == '*' {
					var c1 byte
					for (c != '*' || c1 != '/') && r.err == nil {
						if r.eof {
							r.syntaxError()
						}
						c, c1 = c1, r.readByte()
					}
				} else {
					r.syntaxError()
				}
				c = r.readByte()
				continue
			}
		}
		break
	}
	r.peek = c
	return r.peek
}

// nextByte is like peekByte but advances beyond the returned byte.
func (r *importReader) nextByte(skipSpace bool) byte {
	c := r.peekByte(skipSpace)
	r.peek = 0
	return c
}

var goEmbed = []byte("go:embed")

// findEmbed advances the input reader to the next //go:embed comment.
// It reports whether it found a comment.
// (Otherwise it found an error or EOF.)
func (r *importReader) findEmbed(first bool) bool {
	// The import block scan stopped after a non-space character,
	// so the reader is not at the start of a line on the first call.
	// After that, each //go:embed extraction leaves the reader
	// at the end of a line.
	startLine := !first
	var c byte
	for r.err == nil && !r.eof {
		c = r.readByteNoBuf()
	Reswitch:
		switch c {
		default:
			startLine = false

		case '\n':
			startLine = true

		case ' ', '\t':
			// leave startLine alone

		case '"':
			startLine = false
			for r.err == nil {
				if r.eof {
					r.syntaxError()
				}
				c = r.readByteNoBuf()
				if c == '\\' {
					r.readByteNoBuf()
					if r.err != nil {
						r.syntaxError()
						return false
					}
					continue
				}
				if c == '"' {
					c = r.readByteNoBuf()
					goto Reswitch
				}
			}
			goto Reswitch

		case '`':
			startLine = false
			for r.err == nil {
				if r.eof {
					r.syntaxError()
				}
				c = r.readByteNoBuf()
				if c == '`' {
					c = r.readByteNoBuf()
					goto Reswitch
				}
			}

		case '\'':
			startLine = false
			for r.err == nil {
				if r.eof {
					r.syntaxError()
				}
				c = r.readByteNoBuf()
				if c == '\\' {
					r.readByteNoBuf()
					if r.err != nil {
						r.syntaxError()
						return false
					}
					continue
				}
				if c == '\'' {
					c = r.readByteNoBuf()
					goto Reswitch
				}
			}

		case '/':
			c = r.readByteNoBuf()
			switch c {
			default:
				startLine = false
				goto Reswitch

			case '*':
				var c1 byte
				for (c != '*' || c1 != '/') && r.err == nil {
					if r.eof {
						r.syntaxError()
					}
					c, c1 = c1, r.readByteNoBuf()
				}
				startLine = false

			case '/':
				if startLine {
					// Try to read this as a //go:embed comment.
					for i := range goEmbed {
						c = r.readByteNoBuf()
						if c != goEmbed[i] {
							goto SkipSlashSlash
						}
					}
					c = r.readByteNoBuf()
					if c == ' ' || c == '\t' {
						// Found one!
						return true
					}
				}
			SkipSlashSlash:
				for c != '\n' && r.err == nil && !r.eof {
					c = r.readByteNoBuf()
				}
				startLine = true
			}
		}
	}
	return false
}

// readKeyword reads the given keyword from the input.
// If the keyword is not present, readKeyword records a syntax error.
func (r *importReader) readKeyword(kw string) {
	r.peekByte(true)
	for i := 0; i < len(kw); i++ {
		if r.nextByte(false) != kw[i] {
			r.syntaxError()
			return
		}
	}
	if isIdent(r.peekByte(false)) {
		r.syntaxError()
	}
}

// readIdent reads an identifier from the input.
// If an identifier is not present, readIdent records a syntax error.
func (r *importReader) readIdent() {
	c := r.peekByte(true)
	if !isIdent(c) {
		r.syntaxError()
		return
	}
	for isIdent(r.peekByte(false)) {
		r.peek = 0
	}
}

// readString reads a quoted string literal from the input.
// If an identifier is not present, readString records a syntax error.
func (r *importReader) readString() {
	switch r.nextByte(true) {
	case '`':
		for r.err == nil {
			if r.nextByte(false) == '`' {
				break
			}
			if r.eof {
				r.syntaxError()
			}
		}
	case '"':
		for r.err == nil {
			c := r.nextByte(false)
			if c == '"' {
				break
			}
			if r.eof || c == '\n' {
				r.syntaxError()
			}
			if c == '\\' {
				r.nextByte(false)
			}
		}
	default:
		r.syntaxError()
	}
}

// readImport reads an import clause - optional identifier followed by quoted string -
// from the input.
func (r *importReader) readImport() {
	c := r.peekByte(true)
	if c == '.' {
		r.peek = 0
	} else if isIdent(c) {
		r.readIdent()
	}
	r.readString()
}

// readComments is like io.ReadAll, except that it only reads the leading
// block of comments in the file.
func readComments(f io.Reader) ([]byte, error) {
	r := newImportReader("", f)
	r.peekByte(true)
	if r.err == nil && !r.eof {
		// Didn't reach EOF, so must have found a non-space byte. Remove it.
		r.buf = r.buf[:len(r.buf)-1]
	}
	return r.buf, r.err
}

// readGoInfo expects a Go file as input and reads the file up to and including the import section.
// It records what it learned in *info.
// If info.fset is non-nil, readGoInfo parses the file and sets info.parsed, info.parseErr,
// info.imports and info.embeds.
//
// It only returns an error if there are problems reading the file,
// not for syntax errors in the file itself.
func readGoInfo(f io.Reader, info *fileInfo) error {
	r := newImportReader(info.name, f)

	r.readKeyword("package")
	r.readIdent()
	for r.peekByte(true) == 'i' {
		r.readKeyword("import")
		if r.peekByte(true) == '(' {
			r.nextByte(false)
			for r.peekByte(true) != ')' && r.err == nil {
				r.readImport()
			}
			r.nextByte(false)
		} else {
			r.readImport()
		}
	}

	info.header = r.buf

	// If we stopped successfully before EOF, we read a byte that told us we were done.
	// Return all but that last byte, which would cause a syntax error if we let it through.
	if r.err == nil && !r.eof {
		info.header = r.buf[:len(r.buf)-1]
	}

	// If we stopped for a syntax error, consume the whole file so that
	// we are sure we don't change the errors that go/parser returns.
	if r.err == errSyntax {
		r.err = nil
		for r.err == nil && !r.eof {
			r.readByte()
		}
		info.header = r.buf
	}
	if r.err != nil {
		return r.err
	}

	if info.fset == nil {
		return nil
	}

	// Parse file header & record imports.
	info.parsed, info.parseErr = parser.ParseFile(info.fset, info.name, info.header, parser.ImportsOnly|parser.ParseComments)
	if info.parseErr != nil {
		return nil
	}

	hasEmbed := false
	for _, decl := range info.parsed.Decls {
		d, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, dspec := range d.Specs {
			spec, ok := dspec.(*ast.ImportSpec)
			if !ok {
				continue
			}
			quoted := spec.Path.Value
			path, err := strconv.Unquote(quoted)
			if err != nil {
				return fmt.Errorf("parser returned invalid quoted string: <%s>", quoted)
			}
			if path == "embed" {
				hasEmbed = true
			}

			doc := spec.Doc
			if doc == nil && len(d.Specs) == 1 {
				doc = d.Doc
			}
			info.imports = append(info.imports, fileImport{path, spec.Pos(), doc})
		}
	}

	// Extract directives.
	for _, group := range info.parsed.Comments {
		if group.Pos() >= info.parsed.Package {
			break
		}
		for _, c := range group.List {
			if strings.HasPrefix(c.Text, "//go:") {
				info.directives = append(info.directives, build.Directive{Text: c.Text, Pos: info.fset.Position(c.Slash)})
			}
		}
	}

	// If the file imports "embed",
	// we have to look for //go:embed comments
	// in the remainder of the file.
	// The compiler will enforce the mapping of comments to
	// declared variables. We just need to know the patterns.
	// If there were //go:embed comments earlier in the file
	// (near the package statement or imports), the compiler
	// will reject them. They can be (and have already been) ignored.
	if hasEmbed {
		var line []byte
		for first := true; r.findEmbed(first); first = false {
			line = line[:0]
			pos := r.pos
			for {
				c := r.readByteNoBuf()
				if c == '\n' || r.err != nil || r.eof {
					break
				}
				line = append(line, c)
			}
			// Add args if line is well-formed.
			// Ignore badly-formed lines - the compiler will report them when it finds them,
			// and we can pretend they are not there to help go list succeed with what it knows.
			embs, err := parseGoEmbed(string(line), pos)
			if err == nil {
				info.embeds = append(info.embeds, embs...)
			}
		}
	}

	return nil
}

// parseGoEmbed parses the text following "//go:embed" to extract the glob patterns.
// It accepts unquoted space-separated patterns as well as double-quoted and back-quoted Go strings.
// This is based on a similar function in cmd/compile/internal/gc/noder.go;
// this version calculates position information as well.
func parseGoEmbed(args string, pos token.Position) ([]fileEmbed, error) {
	trimBytes := func(n int) {
		pos.Offset += n
		pos.Column += utf8.RuneCountInString(args[:n])
		args = args[n:]
	}
	trimSpace := func() {
		trim := strings.TrimLeftFunc(args, unicode.IsSpace)
		trimBytes(len(args) - len(trim))
	}

	var list []fileEmbed
	for trimSpace(); args != ""; trimSpace() {
		var path string
		pathPos := pos
	Switch:
		switch args[0] {
		default:
			i := len(args)
			for j, c := range args {
				if unicode.IsSpace(c) {
					i = j
					break
				}
			}
			path = args[:i]
			trimBytes(i)

		case '`':
			var ok bool
			path, _, ok = strings.Cut(args[1:], "`")
			if !ok {
				return nil, fmt.Errorf("invalid quoted string in //go:embed: %s", args)
			}
			trimBytes(1 + len(path) + 1)

		case '"':
			i := 1
			for ; i < len(args); i++ {
				if args[i] == '\\' {
					i++
					continue
				}
				if args[i] == '"' {
					q, err := strconv.Unquote(args[:i+1])
					if err != nil {
						return nil, fmt.Errorf("invalid quoted string in //go:embed: %s", args[:i+1])
					}
					path = q
					trimBytes(i + 1)
					break Switch
				}
			}
			if i >= len(args) {
				return nil, fmt.Errorf("invalid quoted string in //go:embed: %s", args)
			}
		}

		if args != "" {
			r, _ := utf8.DecodeRuneInString(args)
			if !unicode.IsSpace(r) {
				return nil, fmt.Errorf("invalid quoted string in //go:embed: %s", args)
			}
		}
		list = append(list, fileEmbed{path, pathPos})
	}
	return list, nil
}
```