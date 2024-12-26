Response: My thought process to analyze the provided Go code and answer the request goes like this:

1. **Understand the Goal:** The request asks for the functionality of `go/src/cmd/compile/internal/noder/noder.go`, along with examples, command-line argument handling, and common mistakes.

2. **Identify Key Functions and Data Structures:** I'll first scan the code for top-level functions and prominent data structures. This gives a high-level overview. I see `LoadPackage`, `trimFilename`, the `noder` struct, and various helper functions related to pragmas.

3. **Focus on `LoadPackage`:** This function seems to be the entry point for the `noder` package's core responsibility. I'll analyze its steps:
    * **Timing:**  It starts a timer for "parse".
    * **Concurrency:**  It uses a semaphore and goroutines to parse files concurrently. This is a crucial performance optimization.
    * **Error Handling:** It has a channel for collecting errors during parsing.
    * **Syntax Parsing:** It calls `syntax.Parse` to convert the source code into an Abstract Syntax Tree (AST).
    * **Error Reporting:** It aggregates errors from the parsing goroutines.
    * **`unified` function:**  This call is important and suggests a subsequent processing step after parsing. I'll note this down to investigate further (though the provided snippet doesn't contain its implementation).
    * **Line Counting:**  It tracks the number of lines processed.

4. **Analyze the `noder` struct:** This struct holds the state for processing a single file. The important fields are `file` (the syntax.File AST), `linknames`, `pragcgobuf`, and `err`.

5. **Examine Helper Functions:** I'll look at functions called within `LoadPackage` or closely related to the `noder` struct:
    * **`trimFilename`:** This deals with manipulating file paths, likely for consistency in output files. The `-trimpath` flag is mentioned, which is relevant to command-line arguments.
    * **`error`:** A simple error reporting function.
    * **Pragma-related functions (`pragma`, `checkUnusedDuringParse`, `parseGoEmbed`, `isCgoGeneratedFile`, `safeArg`):** These seem to handle compiler directives (pragmas). I'll pay close attention to the different types of pragmas and their parsing logic. The `//go:linkname`, `//go:embed`, `//go:wasmimport`, and `//go:wasmexport` pragmas stand out. The code related to cgo pragmas and the `isCgoGeneratedFile` function indicates handling of interoperability with C code.
    * **`Renameinit`:** This function modifies the name of the `init` function, likely to ensure uniqueness and prevent direct calls.
    * **`checkEmbed`:** This function validates the usage of the `//go:embed` directive.

6. **Infer Functionality:** Based on the analysis, I can infer that this code is a part of the Go compiler responsible for:
    * **Parsing Go source code:** Converting text files into an AST.
    * **Handling compiler directives (pragmas):** Interpreting instructions embedded in comments.
    * **Processing `//go:linkname`:**  Managing symbol linking between packages.
    * **Processing `//go:embed`:**  Embedding file contents into the compiled binary.
    * **Processing `//go:wasmimport` and `//go:wasmexport`:**  Supporting WebAssembly integration.
    * **Handling cgo directives:**  Facilitating interaction with C code.
    * **Renaming `init` functions:**  Ensuring proper initialization.
    * **Basic error reporting.**
    * **Concurrency for faster parsing.**

7. **Construct Examples:** Now I'll create Go code examples to illustrate the inferred functionalities:
    * **`//go:linkname`:**  Demonstrate linking a local Go symbol to an external one.
    * **`//go:embed`:** Show how to embed a text file.
    * **`//go:wasmimport`:** Illustrate importing a WebAssembly function.
    * **`//go:wasmexport`:** Show how to export a Go function to WebAssembly.

8. **Address Command-Line Arguments:** The `-trimpath` flag is explicitly mentioned in `trimFilename`. I'll explain its purpose.

9. **Identify Potential Mistakes:** Based on the code and my understanding of Go, I'll think about common errors users might make:
    * **Misplaced pragmas:**  The code checks for this.
    * **Incorrect `//go:embed` syntax:**  The `parseGoEmbed` function handles this, so I'll highlight common errors in the pattern.
    * **Using cgo directives in non-cgo files:** The code enforces this restriction.

10. **Structure the Answer:** Finally, I'll organize my findings into a clear and structured answer, covering each point in the request: functionalities, code examples, command-line arguments, and common mistakes. I'll use headings and code blocks to improve readability.

This structured approach allows me to systematically analyze the code, understand its purpose, and provide a comprehensive answer to the request. I paid special attention to the comments in the code, which provided valuable clues about the intent of different sections. The presence of specific pragmas like `//go:embed` and `//go:wasmimport` were strong indicators of the features being implemented.
这段代码是Go编译器 `cmd/compile/internal/noder` 包中的 `noder.go` 文件的一部分，其主要功能是将 Go 语法解析器（`cmd/compile/internal/syntax`）生成的抽象语法树 (AST) 转换为编译器内部的中间表示形式 (IR) 的节点树 (`cmd/compile/internal/ir`). 这个过程是 Go 编译器的前端处理的关键步骤。

以下是代码中主要功能的详细解释：

**1. 加载和解析 Go 源文件 (`LoadPackage` 函数):**

*   **功能:**  接收一组文件名作为输入，并发地解析这些文件，并将解析结果存储在 `noder` 结构体中。
*   **实现细节:**
    *   使用 `runtime.GOMAXPROCS` 限制并发打开的文件数量，避免资源耗尽。
    *   为每个文件创建一个 `noder` 实例，用于存储该文件的解析状态和错误信息。
    *   使用 goroutine 并发地打开和解析文件。
    *   调用 `syntax.Parse` 函数执行实际的语法解析，并将解析后的 AST 存储在 `noder.file` 中。
    *   通过 `noder.err` 通道收集解析过程中遇到的语法错误。
    *   `unified(m, noders)`  暗示着解析完成后，会对所有文件的 AST 进行统一处理 (这段代码中没有 `unified` 的具体实现，但可以推断其作用是连接和整合不同文件的 AST)。
*   **Go 代码示例 (假设存在 `example.go` 文件):**

```go
// example.go
package main

import "fmt"

func main() {
	fmt.Println("Hello, world!")
}
```

*   **假设输入:** `filenames = ["example.go"]`
*   **预期输出:**  `LoadPackage` 函数会读取 `example.go` 的内容，调用语法解析器将其转换为 AST，并将 AST 存储在对应的 `noder` 结构体中。如果解析过程中出现错误，错误信息会被发送到 `noder.err` 通道。

**2. 处理 `-trimpath` 命令行参数 (`trimFilename` 函数):**

*   **功能:**  根据 `-trimpath` 命令行参数处理文件名。该参数用于在编译输出（如目标文件和导出数据）中去除文件路径的前缀，使得构建输出更具可移植性和可重现性。
*   **实现细节:**
    *   检查 `syntax.PosBase` 是否已经被裁剪过 (通过 `b.Trimmed()`)。如果是，则直接返回原始文件名。
    *   如果没有被裁剪过，则获取当前编译上下文的路径 (`base.Ctxt.Pathname`) 和提供的文件名，并调用 `objabi.AbsFile` 函数来应用 `-trimpath` 处理。
*   **命令行参数处理:**  `-trimpath` 是 `go build` 等构建工具的命令行参数，会传递给编译器。`base.Flag.TrimPath`  变量存储了该参数的值。
*   **Go 代码示例:**

```bash
go build -trimpath . ./example.go
```

*   **假设输入:**
    *   `b.Filename()` 返回 `/home/user/project/example.go`
    *   `base.Ctxt.Pathname` 返回 `/home/user/project`
    *   `-trimpath` 命令行参数设置为 `.`
*   **预期输出:** `trimFilename(b)` 将返回 `example.go`。路径前缀 `/home/user/project` 被移除。

**3. 存储和管理编译器指令 (`noder` 结构体和相关类型):**

*   **功能:**  `noder` 结构体用于存储单个源文件的解析状态和编译器指令。
*   **实现细节:**
    *   `file`:  存储该文件解析后的 `syntax.File` 类型的 AST。
    *   `linknames`:  存储 `//go:linkname` 指令的信息，用于将本地符号链接到其他包或外部库的符号。
    *   `pragcgobuf`: 存储 `//go:cgo_*` 指令的信息，用于 cgo 相关的操作。
    *   `err`:  用于接收语法解析器发送的错误信息的通道。
*   **`linkname` 结构体:**  表示一个 `//go:linkname` 指令，包含指令所在的位置、本地符号名和远程符号名。
*   **`pragmas` 结构体:**  存储各种编译器指令的信息，包括：
    *   `Flag`:  使用位掩码存储通用的编译器标志。
    *   `Pos`:  存储每个标志的位置信息。
    *   `Embeds`:  存储 `//go:embed` 指令的模式列表。
    *   `WasmImport` 和 `WasmExport`:  存储 `//go:wasmimport` 和 `//go:wasmexport` 指令的信息，用于 WebAssembly 集成。

**4. 处理编译器指令 (`pragma` 函数):**

*   **功能:**  解析和处理 Go 源代码中的编译器指令 (以 `//go:` 开头的注释)。
*   **实现细节:**
    *   接收指令所在的位置、是否为空行、指令文本和之前的 pragma 信息作为输入。
    *   根据指令前缀 (如 `go:linkname`, `go:embed`, `go:wasmimport`) 执行不同的处理逻辑。
    *   **`//go:linkname`:**  解析本地符号名和链接目标，并将其添加到 `noder.linknames` 中。
    *   **`//go:embed`:**  解析嵌入文件的模式，并将其添加到 `pragma.Embeds` 中。
    *   **`//go:wasmimport` 和 `//go:wasmexport`:**  解析 WebAssembly 导入和导出的模块名和符号名，并存储在 `pragma.WasmImport` 和 `pragma.WasmExport` 中。
    *   **`//go:cgo_*`:**  处理 cgo 相关的指令，并进行安全检查，确保这些指令只在 cgo 生成的文件中使用。
    *   其他标准编译器指令也会被解析并设置相应的标志。
*   **Go 代码示例 (使用 `//go:linkname` 和 `//go:embed`):**

```go
package main

import "fmt"

//go:linkname myPrint runtime.printstring
func myPrint(s string)

//go:embed data.txt
var data string

func main() {
	myPrint("Hello from linkname!\n")
	fmt.Println("Embedded data:", data)
}
```

*   **假设输入:**  解析器在扫描到 `//go:linkname myPrint runtime.printstring` 和 `//go:embed data.txt` 时，会调用 `pragma` 函数，并传递相应的信息。
*   **预期输出:**
    *   对于 `//go:linkname`，会创建一个 `linkname` 结构体，存储 `local = "myPrint"` 和 `remote = "runtime.printstring"`，并将其添加到 `noder.linknames` 中。
    *   对于 `//go:embed`，会创建一个 `pragmaEmbed` 结构体，存储模式 `["data.txt"]`，并将其添加到 `pragma.Embeds` 中。

**5. 检查未使用的编译器指令 (`checkUnusedDuringParse` 函数):**

*   **功能:**  在解析过程中检查是否有编译器指令被错误地放置，例如指令不应该出现在类型定义或函数体内部。
*   **实现细节:**  检查 `pragma.Pos` 和其他字段，如果发现指令的位置不正确，则报告一个错误。

**6. 处理二元和一元运算符:**

*   **功能:**  将语法解析器中的运算符表示转换为编译器内部 IR 的运算符表示。
*   **实现细节:**  `unOps` 和 `binOps` 数组分别定义了语法运算符到 IR 运算符的映射。例如，语法中的 `syntax.Add` (加法) 映射到 IR 中的 `ir.OADD`。

**7. 重命名 `init` 函数 (`Renameinit` 函数):**

*   **功能:**  为了防止 `init` 函数被直接调用，并且确保每个包只有一个 `init` 函数，编译器会将 `init` 函数重命名为类似 `pkg.init.0` 的形式。
*   **实现细节:**  使用 `typecheck.LookupNum` 函数创建一个带有递增后缀的唯一符号。

**8. 检查 `//go:embed` 指令的用法 (`checkEmbed` 函数):**

*   **功能:**  对 `//go:embed` 指令的应用进行合法性检查。
*   **检查项:**
    *   是否导入了 `embed` 包。
    *   是否应用到多个变量。
    *   是否在声明时进行了初始化。
    *   是否应用到没有类型的变量。
    *   是否在函数内部使用。
    *   Go 版本是否支持 `//go:embed` (Go 1.16 及更高版本)。

**哪些 Go 语言功能的实现？**

根据代码内容，可以推断出 `noder.go` 参与了以下 Go 语言功能的实现：

*   **`//go:linkname`:**  允许将 Go 函数或变量链接到其他包或外部库中的符号。这通常用于访问运行时包的内部函数或与 C 代码进行互操作。
*   **`//go:embed`:**  允许将静态文件或目录的内容嵌入到编译后的 Go 可执行文件中。
*   **`//go:wasmimport` 和 `//go:wasmexport`:**  支持将 Go 代码编译为 WebAssembly，并允许导入和导出 WebAssembly 模块的功能。
*   **CGO (`//go:cgo_*`)**:  虽然这里只是处理指令的阶段，但 `noder.go` 参与了 CGO 功能的实现，允许在 Go 代码中调用 C 代码。
*   **编译器指令 (Pragmas):**  `noder.go` 负责解析和处理各种以 `//go:` 开头的编译器指令，用于指导编译器的行为。

**使用者易犯错的点:**

*   **错误放置编译器指令:**  编译器指令必须出现在特定的位置（通常是全局作用域的注释行）。将指令放在函数内部或类型定义中会导致编译错误。

    ```go
    package main

    import "fmt"

    func main() {
        //go:linkname myPrint runtime.printstring // 错误：指令在函数内部
        func myPrint(s string)
        fmt.Println("Hello")
    }
    ```

    **错误信息:** `misplaced compiler directive`

*   **`//go:embed` 指令的错误用法:**

    *   **未导入 `embed` 包:** 使用 `//go:embed` 的 Go 文件必须导入 `embed` 包。

        ```go
        package main

        //go:embed data.txt // 错误：未导入 "embed"

        func main() {}
        ```

        **错误信息:** `go:embed only allowed in Go files that import "embed"`

    *   **`//go:embed` 应用于多个变量:**  `//go:embed` 只能应用于单个变量。

        ```go
        package main

        import "embed"

        //go:embed file1.txt file2.txt // 错误：应用于多个变量
        var f1, f2 string

        func main() {}
        ```

        **错误信息:** `go:embed cannot apply to multiple vars`

    *   **`//go:embed` 应用于带初始化的变量:**  `//go:embed` 负责初始化变量，不能同时提供初始值。

        ```go
        package main

        import "embed"

        //go:embed data.txt
        var data string = "initial value" // 错误：变量带有初始化器

        func main() {}
        ```

        **错误信息:** `go:embed cannot apply to var with initializer`

    *   **`//go:embed` 应用于没有类型的变量:**  `//go:embed` 需要知道嵌入数据的类型（通常是 `string` 或 `[]byte`）。

        ```go
        package main

        import "embed"

        //go:embed data.txt
        var data = // 错误：变量没有显式类型

        func main() {}
        ```

        **错误信息:** `go:embed cannot apply to var without type`

    *   **在函数内部使用 `//go:embed`:** `//go:embed` 只能在全局作用域中使用。

        ```go
        package main

        import "embed"

        func main() {
            //go:embed data.txt // 错误：在函数内部
            var data string
        }
        ```

        **错误信息:** `go:embed cannot apply to var inside func`

*   **在非 CGO 文件中使用 CGO 指令:**  为了安全起见，`//go:cgo_*` 指令通常只允许在由 cgo 工具生成的文件中使用。

    ```go
    // not_cgo.go
    package main

    //go:cgo_CFLAGS: -I/usr/include // 错误：在非 cgo 文件中使用 cgo 指令

    func main() {}
    ```

    **错误信息:** `//go:cgo_CFLAGS: -I/usr/include only allowed in cgo-generated code`

理解 `noder.go` 的功能有助于深入了解 Go 编译器的前端处理流程，以及 Go 语言的一些高级特性是如何实现的。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/noder/noder.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package noder

import (
	"errors"
	"fmt"
	"internal/buildcfg"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/syntax"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/objabi"
)

func LoadPackage(filenames []string) {
	base.Timer.Start("fe", "parse")

	// Limit the number of simultaneously open files.
	sem := make(chan struct{}, runtime.GOMAXPROCS(0)+10)

	noders := make([]*noder, len(filenames))
	for i := range noders {
		p := noder{
			err: make(chan syntax.Error),
		}
		noders[i] = &p
	}

	// Move the entire syntax processing logic into a separate goroutine to avoid blocking on the "sem".
	go func() {
		for i, filename := range filenames {
			filename := filename
			p := noders[i]
			sem <- struct{}{}
			go func() {
				defer func() { <-sem }()
				defer close(p.err)
				fbase := syntax.NewFileBase(filename)

				f, err := os.Open(filename)
				if err != nil {
					p.error(syntax.Error{Msg: err.Error()})
					return
				}
				defer f.Close()

				p.file, _ = syntax.Parse(fbase, f, p.error, p.pragma, syntax.CheckBranches) // errors are tracked via p.error
			}()
		}
	}()

	var lines uint
	var m posMap
	for _, p := range noders {
		for e := range p.err {
			base.ErrorfAt(m.makeXPos(e.Pos), 0, "%s", e.Msg)
		}
		if p.file == nil {
			base.ErrorExit()
		}
		lines += p.file.EOF.Line()
	}
	base.Timer.AddEvent(int64(lines), "lines")

	unified(m, noders)
}

// trimFilename returns the "trimmed" filename of b, which is the
// absolute filename after applying -trimpath processing. This
// filename form is suitable for use in object files and export data.
//
// If b's filename has already been trimmed (i.e., because it was read
// in from an imported package's export data), then the filename is
// returned unchanged.
func trimFilename(b *syntax.PosBase) string {
	filename := b.Filename()
	if !b.Trimmed() {
		dir := ""
		if b.IsFileBase() {
			dir = base.Ctxt.Pathname
		}
		filename = objabi.AbsFile(dir, filename, base.Flag.TrimPath)
	}
	return filename
}

// noder transforms package syntax's AST into a Node tree.
type noder struct {
	file       *syntax.File
	linknames  []linkname
	pragcgobuf [][]string
	err        chan syntax.Error
}

// linkname records a //go:linkname directive.
type linkname struct {
	pos    syntax.Pos
	local  string
	remote string
}

var unOps = [...]ir.Op{
	syntax.Recv: ir.ORECV,
	syntax.Mul:  ir.ODEREF,
	syntax.And:  ir.OADDR,

	syntax.Not: ir.ONOT,
	syntax.Xor: ir.OBITNOT,
	syntax.Add: ir.OPLUS,
	syntax.Sub: ir.ONEG,
}

var binOps = [...]ir.Op{
	syntax.OrOr:   ir.OOROR,
	syntax.AndAnd: ir.OANDAND,

	syntax.Eql: ir.OEQ,
	syntax.Neq: ir.ONE,
	syntax.Lss: ir.OLT,
	syntax.Leq: ir.OLE,
	syntax.Gtr: ir.OGT,
	syntax.Geq: ir.OGE,

	syntax.Add: ir.OADD,
	syntax.Sub: ir.OSUB,
	syntax.Or:  ir.OOR,
	syntax.Xor: ir.OXOR,

	syntax.Mul:    ir.OMUL,
	syntax.Div:    ir.ODIV,
	syntax.Rem:    ir.OMOD,
	syntax.And:    ir.OAND,
	syntax.AndNot: ir.OANDNOT,
	syntax.Shl:    ir.OLSH,
	syntax.Shr:    ir.ORSH,
}

// error is called concurrently if files are parsed concurrently.
func (p *noder) error(err error) {
	p.err <- err.(syntax.Error)
}

// pragmas that are allowed in the std lib, but don't have
// a syntax.Pragma value (see lex.go) associated with them.
var allowedStdPragmas = map[string]bool{
	"go:cgo_export_static":  true,
	"go:cgo_export_dynamic": true,
	"go:cgo_import_static":  true,
	"go:cgo_import_dynamic": true,
	"go:cgo_ldflag":         true,
	"go:cgo_dynamic_linker": true,
	"go:embed":              true,
	"go:generate":           true,
}

// *pragmas is the value stored in a syntax.pragmas during parsing.
type pragmas struct {
	Flag       ir.PragmaFlag // collected bits
	Pos        []pragmaPos   // position of each individual flag
	Embeds     []pragmaEmbed
	WasmImport *WasmImport
	WasmExport *WasmExport
}

// WasmImport stores metadata associated with the //go:wasmimport pragma
type WasmImport struct {
	Pos    syntax.Pos
	Module string
	Name   string
}

// WasmExport stores metadata associated with the //go:wasmexport pragma
type WasmExport struct {
	Pos  syntax.Pos
	Name string
}

type pragmaPos struct {
	Flag ir.PragmaFlag
	Pos  syntax.Pos
}

type pragmaEmbed struct {
	Pos      syntax.Pos
	Patterns []string
}

func (p *noder) checkUnusedDuringParse(pragma *pragmas) {
	for _, pos := range pragma.Pos {
		if pos.Flag&pragma.Flag != 0 {
			p.error(syntax.Error{Pos: pos.Pos, Msg: "misplaced compiler directive"})
		}
	}
	if len(pragma.Embeds) > 0 {
		for _, e := range pragma.Embeds {
			p.error(syntax.Error{Pos: e.Pos, Msg: "misplaced go:embed directive"})
		}
	}
	if pragma.WasmImport != nil {
		p.error(syntax.Error{Pos: pragma.WasmImport.Pos, Msg: "misplaced go:wasmimport directive"})
	}
	if pragma.WasmExport != nil {
		p.error(syntax.Error{Pos: pragma.WasmExport.Pos, Msg: "misplaced go:wasmexport directive"})
	}
}

// pragma is called concurrently if files are parsed concurrently.
func (p *noder) pragma(pos syntax.Pos, blankLine bool, text string, old syntax.Pragma) syntax.Pragma {
	pragma, _ := old.(*pragmas)
	if pragma == nil {
		pragma = new(pragmas)
	}

	if text == "" {
		// unused pragma; only called with old != nil.
		p.checkUnusedDuringParse(pragma)
		return nil
	}

	if strings.HasPrefix(text, "line ") {
		// line directives are handled by syntax package
		panic("unreachable")
	}

	if !blankLine {
		// directive must be on line by itself
		p.error(syntax.Error{Pos: pos, Msg: "misplaced compiler directive"})
		return pragma
	}

	switch {
	case strings.HasPrefix(text, "go:wasmimport "):
		f := strings.Fields(text)
		if len(f) != 3 {
			p.error(syntax.Error{Pos: pos, Msg: "usage: //go:wasmimport importmodule importname"})
			break
		}

		if buildcfg.GOARCH == "wasm" {
			// Only actually use them if we're compiling to WASM though.
			pragma.WasmImport = &WasmImport{
				Pos:    pos,
				Module: f[1],
				Name:   f[2],
			}
		}

	case strings.HasPrefix(text, "go:wasmexport "):
		f := strings.Fields(text)
		if len(f) != 2 {
			// TODO: maybe make the name optional? It was once mentioned on proposal 65199.
			p.error(syntax.Error{Pos: pos, Msg: "usage: //go:wasmexport exportname"})
			break
		}

		if buildcfg.GOARCH == "wasm" {
			// Only actually use them if we're compiling to WASM though.
			pragma.WasmExport = &WasmExport{
				Pos:  pos,
				Name: f[1],
			}
		}

	case strings.HasPrefix(text, "go:linkname "):
		f := strings.Fields(text)
		if !(2 <= len(f) && len(f) <= 3) {
			p.error(syntax.Error{Pos: pos, Msg: "usage: //go:linkname localname [linkname]"})
			break
		}
		// The second argument is optional. If omitted, we use
		// the default object symbol name for this and
		// linkname only serves to mark this symbol as
		// something that may be referenced via the object
		// symbol name from another package.
		var target string
		if len(f) == 3 {
			target = f[2]
		} else if base.Ctxt.Pkgpath != "" {
			// Use the default object symbol name if the
			// user didn't provide one.
			target = objabi.PathToPrefix(base.Ctxt.Pkgpath) + "." + f[1]
		} else {
			panic("missing pkgpath")
		}
		p.linknames = append(p.linknames, linkname{pos, f[1], target})

	case text == "go:embed", strings.HasPrefix(text, "go:embed "):
		args, err := parseGoEmbed(text[len("go:embed"):])
		if err != nil {
			p.error(syntax.Error{Pos: pos, Msg: err.Error()})
		}
		if len(args) == 0 {
			p.error(syntax.Error{Pos: pos, Msg: "usage: //go:embed pattern..."})
			break
		}
		pragma.Embeds = append(pragma.Embeds, pragmaEmbed{pos, args})

	case strings.HasPrefix(text, "go:cgo_import_dynamic "):
		// This is permitted for general use because Solaris
		// code relies on it in golang.org/x/sys/unix and others.
		fields := pragmaFields(text)
		if len(fields) >= 4 {
			lib := strings.Trim(fields[3], `"`)
			if lib != "" && !safeArg(lib) && !isCgoGeneratedFile(pos) {
				p.error(syntax.Error{Pos: pos, Msg: fmt.Sprintf("invalid library name %q in cgo_import_dynamic directive", lib)})
			}
			p.pragcgo(pos, text)
			pragma.Flag |= pragmaFlag("go:cgo_import_dynamic")
			break
		}
		fallthrough
	case strings.HasPrefix(text, "go:cgo_"):
		// For security, we disallow //go:cgo_* directives other
		// than cgo_import_dynamic outside cgo-generated files.
		// Exception: they are allowed in the standard library, for runtime and syscall.
		if !isCgoGeneratedFile(pos) && !base.Flag.Std {
			p.error(syntax.Error{Pos: pos, Msg: fmt.Sprintf("//%s only allowed in cgo-generated code", text)})
		}
		p.pragcgo(pos, text)
		fallthrough // because of //go:cgo_unsafe_args
	default:
		verb := text
		if i := strings.Index(text, " "); i >= 0 {
			verb = verb[:i]
		}
		flag := pragmaFlag(verb)
		const runtimePragmas = ir.Systemstack | ir.Nowritebarrier | ir.Nowritebarrierrec | ir.Yeswritebarrierrec
		if !base.Flag.CompilingRuntime && flag&runtimePragmas != 0 {
			p.error(syntax.Error{Pos: pos, Msg: fmt.Sprintf("//%s only allowed in runtime", verb)})
		}
		if flag == ir.UintptrKeepAlive && !base.Flag.Std {
			p.error(syntax.Error{Pos: pos, Msg: fmt.Sprintf("//%s is only allowed in the standard library", verb)})
		}
		if flag == 0 && !allowedStdPragmas[verb] && base.Flag.Std {
			p.error(syntax.Error{Pos: pos, Msg: fmt.Sprintf("//%s is not allowed in the standard library", verb)})
		}
		pragma.Flag |= flag
		pragma.Pos = append(pragma.Pos, pragmaPos{flag, pos})
	}

	return pragma
}

// isCgoGeneratedFile reports whether pos is in a file
// generated by cgo, which is to say a file with name
// beginning with "_cgo_". Such files are allowed to
// contain cgo directives, and for security reasons
// (primarily misuse of linker flags), other files are not.
// See golang.org/issue/23672.
// Note that cmd/go ignores files whose names start with underscore,
// so the only _cgo_ files we will see from cmd/go are generated by cgo.
// It's easy to bypass this check by calling the compiler directly;
// we only protect against uses by cmd/go.
func isCgoGeneratedFile(pos syntax.Pos) bool {
	// We need the absolute file, independent of //line directives,
	// so we call pos.Base().Pos().
	return strings.HasPrefix(filepath.Base(trimFilename(pos.Base().Pos().Base())), "_cgo_")
}

// safeArg reports whether arg is a "safe" command-line argument,
// meaning that when it appears in a command-line, it probably
// doesn't have some special meaning other than its own name.
// This is copied from SafeArg in cmd/go/internal/load/pkg.go.
func safeArg(name string) bool {
	if name == "" {
		return false
	}
	c := name[0]
	return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || c == '.' || c == '_' || c == '/' || c >= utf8.RuneSelf
}

// parseGoEmbed parses the text following "//go:embed" to extract the glob patterns.
// It accepts unquoted space-separated patterns as well as double-quoted and back-quoted Go strings.
// go/build/read.go also processes these strings and contains similar logic.
func parseGoEmbed(args string) ([]string, error) {
	var list []string
	for args = strings.TrimSpace(args); args != ""; args = strings.TrimSpace(args) {
		var path string
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
			args = args[i:]

		case '`':
			i := strings.Index(args[1:], "`")
			if i < 0 {
				return nil, fmt.Errorf("invalid quoted string in //go:embed: %s", args)
			}
			path = args[1 : 1+i]
			args = args[1+i+1:]

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
					args = args[i+1:]
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
		list = append(list, path)
	}
	return list, nil
}

// A function named init is a special case.
// It is called by the initialization before main is run.
// To make it unique within a package and also uncallable,
// the name, normally "pkg.init", is altered to "pkg.init.0".
var renameinitgen int

func Renameinit() *types.Sym {
	s := typecheck.LookupNum("init.", renameinitgen)
	renameinitgen++
	return s
}

func checkEmbed(decl *syntax.VarDecl, haveEmbed, withinFunc bool) error {
	switch {
	case !haveEmbed:
		return errors.New("go:embed only allowed in Go files that import \"embed\"")
	case len(decl.NameList) > 1:
		return errors.New("go:embed cannot apply to multiple vars")
	case decl.Values != nil:
		return errors.New("go:embed cannot apply to var with initializer")
	case decl.Type == nil:
		// Should not happen, since Values == nil now.
		return errors.New("go:embed cannot apply to var without type")
	case withinFunc:
		return errors.New("go:embed cannot apply to var inside func")
	case !types.AllowsGoVersion(1, 16):
		return fmt.Errorf("go:embed requires go1.16 or later (-lang was set to %s; check go.mod)", base.Flag.Lang)

	default:
		return nil
	}
}

"""



```