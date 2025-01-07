Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Goal:**

The request asks for an explanation of the Go code's functionality, specifically the `go/src/go/doc/example.go` file. The key is identifying what this code *does* within the broader context of the `go doc` tool.

**2. Initial Code Scan and Keyword Identification:**

I'd start by quickly scanning the code for keywords and structure. I see:

* `package doc`:  This immediately tells me it's part of the `go/doc` package, likely involved in documentation extraction.
* `type Example struct`:  This is a central data structure. Its fields (`Name`, `Suffix`, `Doc`, `Code`, `Play`, `Output`, etc.) hint at what the code is trying to capture. The names suggest example code extraction and analysis.
* `func Examples(testFiles ...*ast.File) []*Example`: This is a key function. The input `testFiles` and the output `[]*Example` strongly suggest that this function processes Go test files to find examples.
* Comments like "// Extract example functions from file ASTs." reinforce the initial understanding.
* Other helper functions like `exampleOutput`, `isTest`, `playExample`, `findDeclsAndUnresolved`, `classifyExamples` provide further clues about the processing steps.

**3. Deeper Dive into Key Functions:**

* **`Examples` Function:** This is the entry point for extracting examples. I'd analyze its steps:
    * Iterating through `testFiles`.
    * Identifying function declarations (`ast.FuncDecl`).
    * Filtering for functions starting with "Example".
    * Extracting documentation (`f.Doc.Text()`).
    * Calling `exampleOutput` to get the expected output.
    * Potentially marking an example as "playable" based on file content and imports. This warrants closer inspection of the "playable" logic.
    * Sorting the extracted examples.

* **`exampleOutput` Function:**  This function looks for a specific comment format (`// Output:`) at the end of an example function's body to extract the expected output. The `unordered` flag suggests handling variations in output order.

* **`playExample` and `playExampleFile` Functions:** These are crucial for understanding how the code makes examples runnable. They seem to synthesize a `main` package and function by pulling in necessary declarations and imports. The comments about "playground" compatibility and handling `syscall/js` are important.

* **`findDeclsAndUnresolved` Function:** This function looks complex but is essential for making examples playable. It identifies dependencies (other declarations used by the example) and unresolved identifiers (potential missing imports). The handling of `topDecls` and `typMethods` suggests careful tracking of the scope of identifiers.

* **`classifyExamples` Function:** This function associates extracted examples with specific package members (functions, types, methods) based on naming conventions. The logic for splitting the example name (`ExampleFoo_Bar`) and the handling of suffixes are key here.

**4. Inferring the Overall Functionality:**

Based on the analysis of the key components, I can deduce that the `example.go` file is responsible for:

* **Parsing Go test files:** Using the `go/ast` package to analyze the structure of the code.
* **Identifying example functions:**  Looking for functions with names starting with "Example".
* **Extracting example metadata:**  Getting the documentation, code, and expected output.
* **Determining playability:**  Deciding if an example can be run independently.
* **Synthesizing playable code:** Creating a runnable `main` package by including necessary dependencies and imports.
* **Associating examples:** Linking examples to the specific Go language constructs they demonstrate.

**5. Constructing Examples and Explanations:**

Now I can start formulating the answers to the specific questions:

* **Functionality:** List the deduced functions in clear, concise terms.
* **Go Feature Implementation:** The primary feature is the extraction and processing of examples for documentation. The "playable" aspect touches upon the ability to create runnable snippets. I can create a simple Go code example in a `_test.go` file and show how `Examples` would process it.
* **Code Reasoning (Playable Examples):**  Explain the logic in `playExample`, focusing on dependency analysis and import handling. Provide an example showing how dependencies are included in the synthesized `main` function. Highlight the "unresolved identifier" concept.
* **Command-Line Arguments:** Since this code is part of the `go/doc` package, and `go doc` doesn't directly take flags for *example extraction*, I'd clarify this point. The flags are for the broader `go doc` tool.
* **Common Mistakes:**  Think about common errors when writing Go examples, such as incorrect output comments or dependencies on unimported packages. Provide illustrative examples of these mistakes and how the tool might react.

**6. Review and Refinement:**

Finally, I'd review my answers for clarity, accuracy, and completeness. Ensure the Go code examples are correct and easy to understand. Make sure the language is clear and avoids jargon where possible.

This systematic approach, starting with a high-level understanding and gradually drilling down into the details, is crucial for effectively analyzing and explaining complex code like this. The key is to connect the individual pieces of code to the overall purpose and functionality of the software.
这段代码是 Go 语言 `go/doc` 包的一部分，它的主要功能是从 Go 源代码文件（特别是测试文件）中提取示例函数，并提供关于这些示例的信息。  这些信息会被 `go doc` 工具使用，用于生成包的文档，并在文档中展示可执行的示例代码。

以下是它的详细功能列表：

**1. 提取示例函数:**

   - 代码的核心功能是查找并解析 Go 源代码文件中的示例函数。示例函数的名字以 "Example" 开头，例如 `ExampleFunc`, `ExampleType_Method`, `Example_Suffix` 等。
   - `Examples(testFiles ...*ast.File) []*Example` 函数是主要的入口点，它接收一个或多个 `ast.File` 类型的参数（表示 Go 源代码的抽象语法树），并返回一个 `[]*Example`，其中包含了从这些文件中提取的所有示例。

**2. 提取示例的元数据:**

   - 对于每个找到的示例函数，代码会提取以下信息并存储在 `Example` 结构体中：
     - `Name`:  示例所针对的项的名字（例如，函数名、类型名），可能包含可选的后缀。
     - `Suffix`: 示例名称中的后缀部分，不包含前导的 "_"。这通常用于区分针对同一项的不同示例。
     - `Doc`: 示例函数的文档字符串（注释）。
     - `Code`: 示例函数的函数体对应的抽象语法树节点 (`ast.Node`)。
     - `Play`:  一个完整的、可执行的示例程序，形式为 `ast.File`。这是通过分析示例代码的依赖并生成一个独立的 `main` 包来实现的。
     - `Comments`: 示例函数所在文件中的所有注释。
     - `Output`:  示例函数期望的输出。这是通过在示例函数体末尾的注释中查找以 `// Output:` 或 `// Unordered output:` 开头的行来提取的。
     - `Unordered`: 一个布尔值，表示示例的输出是否是无序的（如果输出注释以 `// Unordered output:` 开头）。
     - `EmptyOutput`: 一个布尔值，表示期望的输出为空。
     - `Order`:  示例在源文件中出现的原始顺序。

**3. 推理示例的可执行性 (Playable Examples):**

   - 代码会尝试判断一个示例是否是 "可执行的" (playable)，并将可执行的版本存储在 `Example.Play` 字段中。
   - 一个示例在以下两种情况下被认为是可执行的：
     - **自包含的示例函数:**  示例函数仅引用其他包的标识符（或预声明的标识符，如 "int"），并且测试文件不包含点导入 (`.`).
     - **整个测试文件作为示例:** 测试文件只包含一个示例函数，零个测试、模糊测试或基准测试函数，并且至少包含一个顶级的函数、类型、变量或常量声明（除了示例函数本身）。
   - `playExample` 和 `playExampleFile` 函数负责生成可执行的示例代码。它们会分析示例的依赖，包括引用的类型、函数、变量等，并将这些依赖项包含到一个新的 `main` 包中。

**4. 提取期望的输出:**

   - `exampleOutput(b *ast.BlockStmt, comments []*ast.CommentGroup)` 函数负责从示例函数的函数体 `b` 和文件中的注释 `comments` 中提取期望的输出。
   - 它查找函数体最后一个注释组，并检查该注释是否以 `// Output:` 或 `// Unordered output:` 开头。
   - 如果找到匹配的注释，则提取其后的文本作为期望的输出。

**5. 关联示例到对应的文档项:**

   - `classifyExamples(p *Package, examples []*Example)` 函数将提取出的示例与包 `p` 中的特定函数、类型或方法关联起来。
   - 关联是基于示例函数的名称进行的。例如，`ExampleFoo` 会关联到名为 `Foo` 的函数或类型， `ExampleType_Method` 会关联到 `Type` 类型的 `Method` 方法。

**用 Go 代码举例说明：**

假设我们有以下测试文件 `example_test.go`：

```go
package mypackage_test

import "fmt"

func ExampleHello() {
	fmt.Println("Hello, world!")
	// Output:
	// Hello, world!
}

func ExampleGoodbye() {
	fmt.Println("Goodbye!")
	// Output:
	// Goodbye!
}

type MyType struct{}

func (MyType) ExampleMethod() {
	fmt.Println("Method called")
	// Output:
	// Method called
}

func ExampleMyType_Other() {
	mt := MyType{}
	fmt.Println("Other example")
	// Output:
	// Other example
}
```

当我们使用 `doc.Examples` 函数解析这个文件时，可以得到类似以下的 `[]*Example`：

```go
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
)

func main() {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "example_test.go", `
package mypackage_test

import "fmt"

func ExampleHello() {
	fmt.Println("Hello, world!")
	// Output:
	// Hello, world!
}

func ExampleGoodbye() {
	fmt.Println("Goodbye!")
	// Output:
	// Goodbye!
}

type MyType struct{}

func (MyType) ExampleMethod() {
	fmt.Println("Method called")
	// Output:
	// Method called
}

func ExampleMyType_Other() {
	mt := MyType{}
	fmt.Println("Other example")
	// Output:
	// Other example
}
	`, 0)
	if err != nil {
		log.Fatal(err)
	}

	examples := doc.Examples(node)
	for _, ex := range examples {
		fmt.Printf("Name: %s, Suffix: %s, Doc: %q, Output: %q, Playable: %v\n",
			ex.Name, ex.Suffix, ex.Doc, ex.Output, ex.Play != nil)
		// 这里可以进一步打印 ex.Play 的内容，查看生成的完整的可执行代码
	}
}
```

**假设的输出：**

```
Name: Goodbye, Suffix: , Doc: "", Output: "Goodbye!\n", Playable: true
Name: Hello, Suffix: , Doc: "", Output: "Hello, world!\n", Playable: true
Name: MyType_Method, Suffix: Method, Doc: "", Output: "Method called\n", Playable: true
Name: MyType_Other, Suffix: Other, Doc: "", Output: "Other example\n", Playable: true
```

**代码推理（Playable Examples）:**

假设我们有以下 `example_play_test.go`:

```go
package mypackage_test

import "fmt"

var GlobalVar = "global"

func helperFunc() string {
	return "helper"
}

func ExamplePlayable() {
	fmt.Println(GlobalVar)
	fmt.Println(helperFunc())
	// Output:
	// global
	// helper
}
```

`playExample` 函数会分析 `ExamplePlayable` 函数的函数体，发现它引用了 `GlobalVar` 和 `helperFunc`。然后，它会在同一个文件中查找这些声明，并将它们包含在生成的 `Play` 字段的 `ast.File` 中，使其成为一个可独立执行的程序，大致如下：

```go
package main

import "fmt"

var GlobalVar = "global"

func helperFunc() string {
	return "helper"
}

func main() {
	fmt.Println(GlobalVar)
	fmt.Println(helperFunc())
}
```

**假设的输入和输出：**

- **输入:**  `ast.File` 对象，表示 `example_play_test.go` 文件的 AST。
- **输出:**  `Example` 结构体，其中 `Play` 字段是一个 `*ast.File`，包含了上面所示的合成的 `main` 包代码。

**命令行参数处理：**

这段代码本身不直接处理命令行参数。它是 `go/doc` 包的一部分，而 `go/doc` 包的功能通常被 `go doc` 命令行工具使用。 `go doc` 工具会解析命令行参数，例如要查看文档的包名、函数名等，然后内部会调用 `go/doc` 包的函数来提取和格式化文档信息，包括示例。

**使用者易犯错的点：**

1. **错误的输出注释格式：**

   ```go
   func ExampleWrongOutput() {
       fmt.Println("Hello")
       // Output : Hello  // 注意空格
   }
   ```

   `exampleOutput` 函数会严格匹配 `// Output:` 或 `// Unordered output:`。多余的空格或其他格式错误会导致输出无法被正确提取。

2. **可执行示例依赖了未导入的包或未导出的标识符：**

   ```go
   package mypackage_test

   import "fmt"

   func notExportedHelper() { // 未导出的函数
       fmt.Println("helper")
   }

   func ExampleBadPlayable() {
       notExportedHelper() // 引用了未导出的函数
       // Output:
       // helper
   }
   ```

   `playExample` 函数在尝试生成可执行代码时，如果发现依赖了当前包中未导出的标识符，通常无法成功生成 `Play` 字段，因为生成的 `main` 包无法访问这些未导出的内容。

3. **在非 `_test.go` 文件中编写示例函数：**

   虽然理论上可以在任何 `.go` 文件中编写以 "Example" 开头的函数，但 `doc.Examples` 函数通常用于处理 `_test.go` 文件。如果在非测试文件中编写示例，可能不会被 `go doc` 工具正确识别和处理。

总而言之，这段代码的核心职责是为 Go 的文档工具提供示例代码的提取和处理能力，使得 Go 的文档能够包含可执行的示例，帮助开发者更好地理解和使用 Go 语言的各种特性。

Prompt: 
```
这是路径为go/src/go/doc/example.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Extract example functions from file ASTs.

package doc

import (
	"cmp"
	"go/ast"
	"go/token"
	"internal/lazyregexp"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// An Example represents an example function found in a test source file.
type Example struct {
	Name        string // name of the item being exemplified (including optional suffix)
	Suffix      string // example suffix, without leading '_' (only populated by NewFromFiles)
	Doc         string // example function doc string
	Code        ast.Node
	Play        *ast.File // a whole program version of the example
	Comments    []*ast.CommentGroup
	Output      string // expected output
	Unordered   bool
	EmptyOutput bool // expect empty output
	Order       int  // original source code order
}

// Examples returns the examples found in testFiles, sorted by Name field.
// The Order fields record the order in which the examples were encountered.
// The Suffix field is not populated when Examples is called directly, it is
// only populated by [NewFromFiles] for examples it finds in _test.go files.
//
// Playable Examples must be in a package whose name ends in "_test".
// An Example is "playable" (the Play field is non-nil) in either of these
// circumstances:
//   - The example function is self-contained: the function references only
//     identifiers from other packages (or predeclared identifiers, such as
//     "int") and the test file does not include a dot import.
//   - The entire test file is the example: the file contains exactly one
//     example function, zero test, fuzz test, or benchmark function, and at
//     least one top-level function, type, variable, or constant declaration
//     other than the example function.
func Examples(testFiles ...*ast.File) []*Example {
	var list []*Example
	for _, file := range testFiles {
		hasTests := false // file contains tests, fuzz test, or benchmarks
		numDecl := 0      // number of non-import declarations in the file
		var flist []*Example
		for _, decl := range file.Decls {
			if g, ok := decl.(*ast.GenDecl); ok && g.Tok != token.IMPORT {
				numDecl++
				continue
			}
			f, ok := decl.(*ast.FuncDecl)
			if !ok || f.Recv != nil {
				continue
			}
			numDecl++
			name := f.Name.Name
			if isTest(name, "Test") || isTest(name, "Benchmark") || isTest(name, "Fuzz") {
				hasTests = true
				continue
			}
			if !isTest(name, "Example") {
				continue
			}
			if params := f.Type.Params; len(params.List) != 0 {
				continue // function has params; not a valid example
			}
			if f.Body == nil { // ast.File.Body nil dereference (see issue 28044)
				continue
			}
			var doc string
			if f.Doc != nil {
				doc = f.Doc.Text()
			}
			output, unordered, hasOutput := exampleOutput(f.Body, file.Comments)
			flist = append(flist, &Example{
				Name:        name[len("Example"):],
				Doc:         doc,
				Code:        f.Body,
				Play:        playExample(file, f),
				Comments:    file.Comments,
				Output:      output,
				Unordered:   unordered,
				EmptyOutput: output == "" && hasOutput,
				Order:       len(flist),
			})
		}
		if !hasTests && numDecl > 1 && len(flist) == 1 {
			// If this file only has one example function, some
			// other top-level declarations, and no tests or
			// benchmarks, use the whole file as the example.
			flist[0].Code = file
			flist[0].Play = playExampleFile(file)
		}
		list = append(list, flist...)
	}
	// sort by name
	slices.SortFunc(list, func(a, b *Example) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return list
}

var outputPrefix = lazyregexp.New(`(?i)^[[:space:]]*(unordered )?output:`)

// Extracts the expected output and whether there was a valid output comment.
func exampleOutput(b *ast.BlockStmt, comments []*ast.CommentGroup) (output string, unordered, ok bool) {
	if _, last := lastComment(b, comments); last != nil {
		// test that it begins with the correct prefix
		text := last.Text()
		if loc := outputPrefix.FindStringSubmatchIndex(text); loc != nil {
			if loc[2] != -1 {
				unordered = true
			}
			text = text[loc[1]:]
			// Strip zero or more spaces followed by \n or a single space.
			text = strings.TrimLeft(text, " ")
			if len(text) > 0 && text[0] == '\n' {
				text = text[1:]
			}
			return text, unordered, true
		}
	}
	return "", false, false // no suitable comment found
}

// isTest tells whether name looks like a test, example, fuzz test, or
// benchmark. It is a Test (say) if there is a character after Test that is not
// a lower-case letter. (We don't want Testiness.)
func isTest(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) { // "Test" is ok
		return true
	}
	rune, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(rune)
}

// playExample synthesizes a new *ast.File based on the provided
// file with the provided function body as the body of main.
func playExample(file *ast.File, f *ast.FuncDecl) *ast.File {
	body := f.Body

	if !strings.HasSuffix(file.Name.Name, "_test") {
		// We don't support examples that are part of the
		// greater package (yet).
		return nil
	}

	// Collect top-level declarations in the file.
	topDecls := make(map[*ast.Object]ast.Decl)
	typMethods := make(map[string][]ast.Decl)

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil {
				topDecls[d.Name.Obj] = d
			} else {
				if len(d.Recv.List) == 1 {
					t := d.Recv.List[0].Type
					tname, _ := baseTypeName(t)
					typMethods[tname] = append(typMethods[tname], d)
				}
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					topDecls[s.Name.Obj] = d
				case *ast.ValueSpec:
					for _, name := range s.Names {
						topDecls[name.Obj] = d
					}
				}
			}
		}
	}

	// Find unresolved identifiers and uses of top-level declarations.
	depDecls, unresolved := findDeclsAndUnresolved(body, topDecls, typMethods)

	// Remove predeclared identifiers from unresolved list.
	for n := range unresolved {
		if predeclaredTypes[n] || predeclaredConstants[n] || predeclaredFuncs[n] {
			delete(unresolved, n)
		}
	}

	// Use unresolved identifiers to determine the imports used by this
	// example. The heuristic assumes package names match base import
	// paths for imports w/o renames (should be good enough most of the time).
	var namedImports []ast.Spec
	var blankImports []ast.Spec // _ imports

	// To preserve the blank lines between groups of imports, find the
	// start position of each group, and assign that position to all
	// imports from that group.
	groupStarts := findImportGroupStarts(file.Imports)
	groupStart := func(s *ast.ImportSpec) token.Pos {
		for i, start := range groupStarts {
			if s.Path.ValuePos < start {
				return groupStarts[i-1]
			}
		}
		return groupStarts[len(groupStarts)-1]
	}

	for _, s := range file.Imports {
		p, err := strconv.Unquote(s.Path.Value)
		if err != nil {
			continue
		}
		if p == "syscall/js" {
			// We don't support examples that import syscall/js,
			// because the package syscall/js is not available in the playground.
			return nil
		}
		n := path.Base(p)
		if s.Name != nil {
			n = s.Name.Name
			switch n {
			case "_":
				blankImports = append(blankImports, s)
				continue
			case ".":
				// We can't resolve dot imports (yet).
				return nil
			}
		}
		if unresolved[n] {
			// Copy the spec and its path to avoid modifying the original.
			spec := *s
			path := *s.Path
			spec.Path = &path
			spec.Path.ValuePos = groupStart(&spec)
			namedImports = append(namedImports, &spec)
			delete(unresolved, n)
		}
	}

	// If there are other unresolved identifiers, give up because this
	// synthesized file is not going to build.
	if len(unresolved) > 0 {
		return nil
	}

	// Include documentation belonging to blank imports.
	var comments []*ast.CommentGroup
	for _, s := range blankImports {
		if c := s.(*ast.ImportSpec).Doc; c != nil {
			comments = append(comments, c)
		}
	}

	// Include comments that are inside the function body.
	for _, c := range file.Comments {
		if body.Pos() <= c.Pos() && c.End() <= body.End() {
			comments = append(comments, c)
		}
	}

	// Strip the "Output:" or "Unordered output:" comment and adjust body
	// end position.
	body, comments = stripOutputComment(body, comments)

	// Include documentation belonging to dependent declarations.
	for _, d := range depDecls {
		switch d := d.(type) {
		case *ast.GenDecl:
			if d.Doc != nil {
				comments = append(comments, d.Doc)
			}
		case *ast.FuncDecl:
			if d.Doc != nil {
				comments = append(comments, d.Doc)
			}
		}
	}

	// Synthesize import declaration.
	importDecl := &ast.GenDecl{
		Tok:    token.IMPORT,
		Lparen: 1, // Need non-zero Lparen and Rparen so that printer
		Rparen: 1, // treats this as a factored import.
	}
	importDecl.Specs = append(namedImports, blankImports...)

	// Synthesize main function.
	funcDecl := &ast.FuncDecl{
		Name: ast.NewIdent("main"),
		Type: f.Type,
		Body: body,
	}

	decls := make([]ast.Decl, 0, 2+len(depDecls))
	decls = append(decls, importDecl)
	decls = append(decls, depDecls...)
	decls = append(decls, funcDecl)

	slices.SortFunc(decls, func(a, b ast.Decl) int {
		return cmp.Compare(a.Pos(), b.Pos())
	})
	slices.SortFunc(comments, func(a, b *ast.CommentGroup) int {
		return cmp.Compare(a.Pos(), b.Pos())
	})

	// Synthesize file.
	return &ast.File{
		Name:     ast.NewIdent("main"),
		Decls:    decls,
		Comments: comments,
	}
}

// findDeclsAndUnresolved returns all the top-level declarations mentioned in
// the body, and a set of unresolved symbols (those that appear in the body but
// have no declaration in the program).
//
// topDecls maps objects to the top-level declaration declaring them (not
// necessarily obj.Decl, as obj.Decl will be a Spec for GenDecls, but
// topDecls[obj] will be the GenDecl itself).
func findDeclsAndUnresolved(body ast.Node, topDecls map[*ast.Object]ast.Decl, typMethods map[string][]ast.Decl) ([]ast.Decl, map[string]bool) {
	// This function recursively finds every top-level declaration used
	// transitively by the body, populating usedDecls and usedObjs. Then it
	// trims down the declarations to include only the symbols actually
	// referenced by the body.

	unresolved := make(map[string]bool)
	var depDecls []ast.Decl
	usedDecls := make(map[ast.Decl]bool)   // set of top-level decls reachable from the body
	usedObjs := make(map[*ast.Object]bool) // set of objects reachable from the body (each declared by a usedDecl)

	var inspectFunc func(ast.Node) bool
	inspectFunc = func(n ast.Node) bool {
		switch e := n.(type) {
		case *ast.Ident:
			if e.Obj == nil && e.Name != "_" {
				unresolved[e.Name] = true
			} else if d := topDecls[e.Obj]; d != nil {

				usedObjs[e.Obj] = true
				if !usedDecls[d] {
					usedDecls[d] = true
					depDecls = append(depDecls, d)
				}
			}
			return true
		case *ast.SelectorExpr:
			// For selector expressions, only inspect the left hand side.
			// (For an expression like fmt.Println, only add "fmt" to the
			// set of unresolved names, not "Println".)
			ast.Inspect(e.X, inspectFunc)
			return false
		case *ast.KeyValueExpr:
			// For key value expressions, only inspect the value
			// as the key should be resolved by the type of the
			// composite literal.
			ast.Inspect(e.Value, inspectFunc)
			return false
		}
		return true
	}

	inspectFieldList := func(fl *ast.FieldList) {
		if fl != nil {
			for _, f := range fl.List {
				ast.Inspect(f.Type, inspectFunc)
			}
		}
	}

	// Find the decls immediately referenced by body.
	ast.Inspect(body, inspectFunc)
	// Now loop over them, adding to the list when we find a new decl that the
	// body depends on. Keep going until we don't find anything new.
	for i := 0; i < len(depDecls); i++ {
		switch d := depDecls[i].(type) {
		case *ast.FuncDecl:
			// Inspect type parameters.
			inspectFieldList(d.Type.TypeParams)
			// Inspect types of parameters and results. See #28492.
			inspectFieldList(d.Type.Params)
			inspectFieldList(d.Type.Results)

			// Functions might not have a body. See #42706.
			if d.Body != nil {
				ast.Inspect(d.Body, inspectFunc)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					inspectFieldList(s.TypeParams)
					ast.Inspect(s.Type, inspectFunc)
					depDecls = append(depDecls, typMethods[s.Name.Name]...)
				case *ast.ValueSpec:
					if s.Type != nil {
						ast.Inspect(s.Type, inspectFunc)
					}
					for _, val := range s.Values {
						ast.Inspect(val, inspectFunc)
					}
				}
			}
		}
	}

	// Some decls include multiple specs, such as a variable declaration with
	// multiple variables on the same line, or a parenthesized declaration. Trim
	// the declarations to include only the specs that are actually mentioned.
	// However, if there is a constant group with iota, leave it all: later
	// constant declarations in the group may have no value and so cannot stand
	// on their own, and removing any constant from the group could change the
	// values of subsequent ones.
	// See testdata/examples/iota.go for a minimal example.
	var ds []ast.Decl
	for _, d := range depDecls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			ds = append(ds, d)
		case *ast.GenDecl:
			containsIota := false // does any spec have iota?
			// Collect all Specs that were mentioned in the example.
			var specs []ast.Spec
			for _, s := range d.Specs {
				switch s := s.(type) {
				case *ast.TypeSpec:
					if usedObjs[s.Name.Obj] {
						specs = append(specs, s)
					}
				case *ast.ValueSpec:
					if !containsIota {
						containsIota = hasIota(s)
					}
					// A ValueSpec may have multiple names (e.g. "var a, b int").
					// Keep only the names that were mentioned in the example.
					// Exception: the multiple names have a single initializer (which
					// would be a function call with multiple return values). In that
					// case, keep everything.
					if len(s.Names) > 1 && len(s.Values) == 1 {
						specs = append(specs, s)
						continue
					}
					ns := *s
					ns.Names = nil
					ns.Values = nil
					for i, n := range s.Names {
						if usedObjs[n.Obj] {
							ns.Names = append(ns.Names, n)
							if s.Values != nil {
								ns.Values = append(ns.Values, s.Values[i])
							}
						}
					}
					if len(ns.Names) > 0 {
						specs = append(specs, &ns)
					}
				}
			}
			if len(specs) > 0 {
				// Constant with iota? Keep it all.
				if d.Tok == token.CONST && containsIota {
					ds = append(ds, d)
				} else {
					// Synthesize a GenDecl with just the Specs we need.
					nd := *d // copy the GenDecl
					nd.Specs = specs
					if len(specs) == 1 {
						// Remove grouping parens if there is only one spec.
						nd.Lparen = 0
					}
					ds = append(ds, &nd)
				}
			}
		}
	}
	return ds, unresolved
}

func hasIota(s ast.Spec) bool {
	has := false
	ast.Inspect(s, func(n ast.Node) bool {
		// Check that this is the special built-in "iota" identifier, not
		// a user-defined shadow.
		if id, ok := n.(*ast.Ident); ok && id.Name == "iota" && id.Obj == nil {
			has = true
			return false
		}
		return true
	})
	return has
}

// findImportGroupStarts finds the start positions of each sequence of import
// specs that are not separated by a blank line.
func findImportGroupStarts(imps []*ast.ImportSpec) []token.Pos {
	startImps := findImportGroupStarts1(imps)
	groupStarts := make([]token.Pos, len(startImps))
	for i, imp := range startImps {
		groupStarts[i] = imp.Pos()
	}
	return groupStarts
}

// Helper for findImportGroupStarts to ease testing.
func findImportGroupStarts1(origImps []*ast.ImportSpec) []*ast.ImportSpec {
	// Copy to avoid mutation.
	imps := make([]*ast.ImportSpec, len(origImps))
	copy(imps, origImps)
	// Assume the imports are sorted by position.
	slices.SortFunc(imps, func(a, b *ast.ImportSpec) int {
		return cmp.Compare(a.Pos(), b.Pos())
	})
	// Assume gofmt has been applied, so there is a blank line between adjacent imps
	// if and only if they are more than 2 positions apart (newline, tab).
	var groupStarts []*ast.ImportSpec
	prevEnd := token.Pos(-2)
	for _, imp := range imps {
		if imp.Pos()-prevEnd > 2 {
			groupStarts = append(groupStarts, imp)
		}
		prevEnd = imp.End()
		// Account for end-of-line comments.
		if imp.Comment != nil {
			prevEnd = imp.Comment.End()
		}
	}
	return groupStarts
}

// playExampleFile takes a whole file example and synthesizes a new *ast.File
// such that the example is function main in package main.
func playExampleFile(file *ast.File) *ast.File {
	// Strip copyright comment if present.
	comments := file.Comments
	if len(comments) > 0 && strings.HasPrefix(comments[0].Text(), "Copyright") {
		comments = comments[1:]
	}

	// Copy declaration slice, rewriting the ExampleX function to main.
	var decls []ast.Decl
	for _, d := range file.Decls {
		if f, ok := d.(*ast.FuncDecl); ok && isTest(f.Name.Name, "Example") {
			// Copy the FuncDecl, as it may be used elsewhere.
			newF := *f
			newF.Name = ast.NewIdent("main")
			newF.Body, comments = stripOutputComment(f.Body, comments)
			d = &newF
		}
		decls = append(decls, d)
	}

	// Copy the File, as it may be used elsewhere.
	f := *file
	f.Name = ast.NewIdent("main")
	f.Decls = decls
	f.Comments = comments
	return &f
}

// stripOutputComment finds and removes the "Output:" or "Unordered output:"
// comment from body and comments, and adjusts the body block's end position.
func stripOutputComment(body *ast.BlockStmt, comments []*ast.CommentGroup) (*ast.BlockStmt, []*ast.CommentGroup) {
	// Do nothing if there is no "Output:" or "Unordered output:" comment.
	i, last := lastComment(body, comments)
	if last == nil || !outputPrefix.MatchString(last.Text()) {
		return body, comments
	}

	// Copy body and comments, as the originals may be used elsewhere.
	newBody := &ast.BlockStmt{
		Lbrace: body.Lbrace,
		List:   body.List,
		Rbrace: last.Pos(),
	}
	newComments := make([]*ast.CommentGroup, len(comments)-1)
	copy(newComments, comments[:i])
	copy(newComments[i:], comments[i+1:])
	return newBody, newComments
}

// lastComment returns the last comment inside the provided block.
func lastComment(b *ast.BlockStmt, c []*ast.CommentGroup) (i int, last *ast.CommentGroup) {
	if b == nil {
		return
	}
	pos, end := b.Pos(), b.End()
	for j, cg := range c {
		if cg.Pos() < pos {
			continue
		}
		if cg.End() > end {
			break
		}
		i, last = j, cg
	}
	return
}

// classifyExamples classifies examples and assigns them to the Examples field
// of the relevant Func, Type, or Package that the example is associated with.
//
// The classification process is ambiguous in some cases:
//
//   - ExampleFoo_Bar matches a type named Foo_Bar
//     or a method named Foo.Bar.
//   - ExampleFoo_bar matches a type named Foo_bar
//     or Foo (with a "bar" suffix).
//
// Examples with malformed names are not associated with anything.
func classifyExamples(p *Package, examples []*Example) {
	if len(examples) == 0 {
		return
	}
	// Mapping of names for funcs, types, and methods to the example listing.
	ids := make(map[string]*[]*Example)
	ids[""] = &p.Examples // package-level examples have an empty name
	for _, f := range p.Funcs {
		if !token.IsExported(f.Name) {
			continue
		}
		ids[f.Name] = &f.Examples
	}
	for _, t := range p.Types {
		if !token.IsExported(t.Name) {
			continue
		}
		ids[t.Name] = &t.Examples
		for _, f := range t.Funcs {
			if !token.IsExported(f.Name) {
				continue
			}
			ids[f.Name] = &f.Examples
		}
		for _, m := range t.Methods {
			if !token.IsExported(m.Name) {
				continue
			}
			ids[strings.TrimPrefix(nameWithoutInst(m.Recv), "*")+"_"+m.Name] = &m.Examples
		}
	}

	// Group each example with the associated func, type, or method.
	for _, ex := range examples {
		// Consider all possible split points for the suffix
		// by starting at the end of string (no suffix case),
		// then trying all positions that contain a '_' character.
		//
		// An association is made on the first successful match.
		// Examples with malformed names that match nothing are skipped.
		for i := len(ex.Name); i >= 0; i = strings.LastIndexByte(ex.Name[:i], '_') {
			prefix, suffix, ok := splitExampleName(ex.Name, i)
			if !ok {
				continue
			}
			exs, ok := ids[prefix]
			if !ok {
				continue
			}
			ex.Suffix = suffix
			*exs = append(*exs, ex)
			break
		}
	}

	// Sort list of example according to the user-specified suffix name.
	for _, exs := range ids {
		slices.SortFunc(*exs, func(a, b *Example) int {
			return cmp.Compare(a.Suffix, b.Suffix)
		})
	}
}

// nameWithoutInst returns name if name has no brackets. If name contains
// brackets, then it returns name with all the contents between (and including)
// the outermost left and right bracket removed.
//
// Adapted from debug/gosym/symtab.go:Sym.nameWithoutInst.
func nameWithoutInst(name string) string {
	start := strings.Index(name, "[")
	if start < 0 {
		return name
	}
	end := strings.LastIndex(name, "]")
	if end < 0 {
		// Malformed name, should contain closing bracket too.
		return name
	}
	return name[0:start] + name[end+1:]
}

// splitExampleName attempts to split example name s at index i,
// and reports if that produces a valid split. The suffix may be
// absent. Otherwise, it must start with a lower-case letter and
// be preceded by '_'.
//
// One of i == len(s) or s[i] == '_' must be true.
func splitExampleName(s string, i int) (prefix, suffix string, ok bool) {
	if i == len(s) {
		return s, "", true
	}
	if i == len(s)-1 {
		return "", "", false
	}
	prefix, suffix = s[:i], s[i+1:]
	return prefix, suffix, isExampleSuffix(suffix)
}

func isExampleSuffix(s string) bool {
	r, size := utf8.DecodeRuneInString(s)
	return size > 0 && unicode.IsLower(r)
}

"""



```