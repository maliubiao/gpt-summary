Response:
Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Understanding and Goal:**

The core request is to understand the functionality of the `package_bin.go` file within the `gocode` project. The decomposed requests are:

* List its functionalities.
* Infer its purpose within the broader Go ecosystem and provide a code example.
* Explain code reasoning with hypothetical inputs and outputs.
* Detail command-line argument handling (if any).
* Identify common user errors.

**2. High-Level Analysis - Identifying the Core Object:**

The code defines a struct `gc_bin_parser`. This immediately suggests the primary purpose: *parsing*. The name "gc_bin" hints at the input format – likely the binary output of the Go compiler (`gc`). The presence of methods like `parse_export`, `obj`, `typ`, `string`, `int`, etc., reinforces the idea of parsing a binary structure.

**3. Dissecting Key Methods and Fields:**

* **`gc_bin_parser` struct:** The fields provide clues about the parsing process:
    * `data []byte`:  The raw binary data being parsed.
    * `version int`:  Indicates the version of the binary format.
    * `strList`, `pathList`, `pkgList`, `typList`:  These look like symbol tables or caches to avoid redundant processing of strings, paths, packages, and types.
    * `callback func(pkg string, decl ast.Decl)`:  This is a crucial point. It suggests the parser extracts declarations (constants, types, variables, functions) and passes them to a callback function. This implies the parser's goal is to *extract information* about a Go package.
    * `pfc *package_file_cache`: Likely a helper struct to manage package information.
    * `posInfoFormat`, `prevFile`, `prevLine`:  Related to tracking source code positions, important for code navigation and tooling.
    * `debugFormat`, `read`: For debugging the parsing process itself.

* **`init`:** Simple initialization of the parser state.

* **`parse_export`:** This is the main entry point. It handles:
    * Reading the binary format version.
    * Populating the `typList` with predeclared types.
    * Reading package information (`pkg()`).
    * Iterating through objects (declarations) using a tag-based system (`tagOrIndex()`, `obj()`).
    * Self-verification of the object count.

* **`pkg`:**  Handles reading package information from the binary data, including name and path. It also seems to maintain a list of encountered packages.

* **`obj`:**  This is a dispatcher based on the `tag`. It handles different types of declarations (`constTag`, `aliasTag`, `typeTag`, `varTag`, `funcTag`) and converts the binary representation into `ast.Decl` objects. This directly connects to the idea of extracting Go language constructs.

* **`typ`:**  Parses type information. It's recursive and handles various type kinds (named, array, slice, struct, pointer, etc.). Crucially, it uses `tagOrIndex()` to check for already seen types (for efficiency and handling recursive type definitions).

* **Low-level methods (`tagOrIndex`, `int`, `int64`, `path`, `string`, `rawByte`):**  These handle the raw reading and decoding of data from the byte slice. The escaping logic with '|' is a detail of the specific binary format.

**4. Inferring the Purpose and Connecting to `gocode`:**

The filename `package_bin.go` and the parsing logic strongly suggest this code is responsible for reading and interpreting the *compiled package information*. Go compilers typically produce `.a` files (archive files) containing compiled code and metadata about the package's exported symbols. This file likely parses the metadata section of those `.a` files.

Knowing this is part of `gocode`, a Go autocompletion daemon, the purpose becomes clear:  `gocode` needs to understand the structure and exported symbols of Go packages to provide accurate code completion suggestions. This parser is a crucial component for achieving that.

**5. Developing the Code Example:**

To illustrate how this parser is used, we need to simulate the scenario of `gocode` reading a package's export data. This involves:

* Having a sample `.a` file (or the relevant export data within it). Since we don't have a real `.a` file readily available in this context, we need to *imagine* its contents and how the parser would interpret it.
* Creating a `package_file_cache` (or a simplified version for the example).
* Implementing a callback function that receives the parsed declarations.
* Running the `parse_export` method.

The example should showcase the extraction of different declaration types (constant, type, function).

**6. Considering Inputs, Outputs, and Error Handling:**

The input to the `parse_export` function is the byte slice containing the compiled package information. The output is the stream of `ast.Decl` objects passed to the callback function.

Error handling is evident in the `panic` calls within the parser, which occur when unexpected tags or format versions are encountered.

**7. Command-Line Arguments and User Errors:**

Based on the code, there's no direct command-line argument parsing *within this specific file*. The `gocode` tool itself likely has command-line arguments, but this file is an internal component.

Common user errors related to *using* `gocode` might involve:

* Incorrectly configured `GOPATH`.
* Issues with the Go environment preventing `gocode` from finding package files.
* Outdated versions of `gocode`.

However, the request asks for errors *related to this specific file*. Since it's an internal parser, users don't directly interact with it. Therefore, it's reasonable to state that there are no direct user errors related to this specific file, but rather potential issues in the broader context of `gocode` usage.

**8. Structuring the Answer:**

Finally, the information needs to be organized clearly, addressing each part of the original request: functionalities, inferred purpose with example, input/output/reasoning, command-line arguments, and user errors. Using clear headings and code formatting enhances readability.

This step-by-step analysis, focusing on understanding the code's structure, methods, and data flow, allows for a comprehensive understanding of the `package_bin.go` file's role within the `gocode` project.
这段代码是Go语言工具 `gocode` 的一部分，它的主要功能是**解析Go编译器（`gc`）生成的包的导出信息（export data）**。

更具体地说，这个文件中的 `gc_bin_parser` 结构体和相关方法实现了从二进制格式的导出数据中提取出Go语言的各种声明（declarations），例如常量、类型、变量和函数等。这些导出数据通常存储在 `.a` 文件中，包含了编译后的包的公共接口信息。

**以下是 `package_bin.go` 的具体功能列表：**

1. **读取和解析导出数据头:**
   - 识别导出数据的版本信息，支持旧版本（Go 1.7 及更早）和新版本（Go 1.8 及以后）的格式。
   - 根据版本信息设置相应的解析标志，例如是否包含调试信息 (`debugFormat`)，是否跟踪所有类型 (`trackAllTypes`)，以及位置信息的格式 (`posInfoFormat`)。

2. **解析包信息:**
   - 读取包的名称和路径。
   - 将解析到的包信息存储在 `pkgList` 中。

3. **解析各种类型的声明:**
   - **常量 (const):**  解析常量名、类型，但忽略常量的值（因为 `gocode` 主要关注代码结构和类型信息）。
   - **类型别名 (alias):** 解析类型别名和其指向的类型。
   - **类型定义 (type):** 解析类型定义的名称和底层类型。对于接口类型，还会解析其内嵌的类型和方法。对于结构体类型，会解析其字段。
   - **变量 (var):** 解析变量名和类型。
   - **函数 (func):** 解析函数名、参数列表和返回值列表。

4. **处理类型信息:**
   - 解析各种类型，包括基本类型、数组、切片、指针、结构体、接口、Map 和 Channel。
   - 使用 `typList` 来缓存已经解析过的类型，避免重复解析，并处理循环引用的类型。

5. **处理位置信息:**
   - 如果导出数据包含位置信息 (`posInfoFormat` 为 `true`)，则解析源文件的文件名和行号。

6. **低级数据读取:**
   - 提供了 `rawByte`, `rawInt64`, `string`, `path` 等方法，用于从字节数组中读取不同类型的数据。
   - 使用 Varint 编码读取整数，使用特定的转义规则处理字符串和路径。

7. **使用回调函数:**
   - 通过 `callback func(string, ast.Decl)` 将解析出的声明传递给调用者。`gocode` 使用这个回调函数来构建包的符号表。

**它是什么go语言功能的实现？**

这段代码是 **Go语言包的元数据解析器** 的实现。Go编译器在编译包时，会生成包含包的公共接口信息的导出数据。`gocode` 需要读取这些信息才能提供代码补全、跳转到定义等功能。

**Go代码举例说明:**

假设我们有一个名为 `mypackage` 的包，其源代码如下：

```go
// mypackage/mypackage.go
package mypackage

const MyConstant = 10

type MyType struct {
    Field1 int
    Field2 string
}

func MyFunction(a int) string {
    return "hello"
}
```

Go编译器会生成 `mypackage.a` 文件，其中包含了 `mypackage` 的导出信息。 `gc_bin_parser` 的作用就是读取并解析 `mypackage.a` 中的导出数据。

**假设的输入与输出：**

**输入:** `gc_bin_parser` 的 `data` 字段会填充 `mypackage.a` 文件中导出数据部分的字节流。

**输出:** 通过 `callback` 函数，`gc_bin_parser` 会产生以下 `ast.Decl` 类型的输出（简化表示）：

```go
// 假设 callback 函数将接收到的声明打印出来
func myCallback(pkg string, decl ast.Decl) {
    fmt.Printf("Package: %s, Declaration: %+v\n", pkg, decl)
}

// 模拟调用 parse_export
parser := gc_bin_parser{/* ... */, callback: myCallback}
parser.parse_export(myCallback)

// 可能的输出（顺序可能不同，具体内容依赖于导出数据的格式）
// Package: !mypackage!mypackage, Declaration: &ast.GenDecl{Tok:const, Specs:[]ast.Spec{...}} // MyConstant
// Package: !mypackage!mypackage, Declaration: &ast.GenDecl{Tok:type, Specs:[]ast.Spec{...}}  // MyType
// Package: !mypackage!mypackage, Declaration: &ast.FuncDecl{Name:MyFunction, Type:...}     // MyFunction
```

**代码推理:**

- 当 `parse_export` 被调用时，它首先读取版本信息。
- 然后，`pkg()` 方法会被调用来解析包名 "mypackage"。
- 接下来，代码会循环读取对象 (declarations) 的标签。
- 当遇到 `constTag` 时，`obj()` 方法会调用 `qualifiedName()` 读取常量名 "MyConstant"，调用 `typ("")` 读取常量类型（可能被解析为预定义的 `int` 类型），并创建一个 `ast.GenDecl` 表示常量声明。
- 类似地，当遇到 `typeTag` 时，会解析类型名 "MyType" 和其结构体定义，创建一个 `ast.GenDecl` 表示类型声明。
- 当遇到 `funcTag` 时，会解析函数名 "MyFunction"、参数列表 `(a int)` 和返回值列表 `string`，创建一个 `ast.FuncDecl` 表示函数声明。

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。`gocode` 工具在运行时会接收命令行参数，例如指定要分析的代码文件或包的路径。但是，`package_bin.go` 作为一个内部模块，其输入是已经加载的包的导出数据。

**使用者易犯错的点:**

由于 `package_bin.go` 是 `gocode` 的内部实现，普通 Go 开发者不会直接与其交互，因此不存在使用者容易犯错的点。这个文件的开发者需要非常了解 Go 编译器的导出数据格式。

然而，对于 `gocode` 的使用者来说，一些可能导致 `gocode` 无法正确工作的常见错误包括：

1. **`GOPATH` 配置不正确:** `gocode` 需要能够找到项目依赖的包，这依赖于正确的 `GOPATH` 设置。
2. **依赖包未安装或编译:** 如果项目依赖的包没有安装或编译，`gocode` 可能无法找到其导出信息。
3. **`gocode` 版本过旧:**  旧版本的 `gocode` 可能不支持新版本的 Go 编译器生成的导出数据格式。
4. **编辑器集成问题:** 编辑器与 `gocode` 的集成配置不当可能导致代码补全等功能失效。

总结来说，`go/src/github.com/nsf/gocode/package_bin.go` 是 `gocode` 的核心组件之一，负责解析 Go 编译器生成的包导出信息，使得 `gocode` 能够理解 Go 代码的结构和类型信息，从而提供代码补全等功能。它是一个底层的、与编译器输出格式紧密相关的解析器。

Prompt: 
```
这是路径为go/src/github.com/nsf/gocode/package_bin.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package main

import (
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/token"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

//-------------------------------------------------------------------------
// gc_bin_parser
//
// The following part of the code may contain portions of the code from the Go
// standard library, which tells me to retain their copyright notice:
//
// Copyright (c) 2012 The Go Authors. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//-------------------------------------------------------------------------

type gc_bin_parser struct {
	data    []byte
	buf     []byte // for reading strings
	version int    // export format version

	// object lists
	strList       []string   // in order of appearance
	pathList      []string   // in order of appearance
	pkgList       []string   // in order of appearance
	typList       []ast.Expr // in order of appearance
	callback      func(pkg string, decl ast.Decl)
	pfc           *package_file_cache
	trackAllTypes bool

	// position encoding
	posInfoFormat bool
	prevFile      string
	prevLine      int

	// debugging support
	debugFormat bool
	read        int // bytes read

}

func (p *gc_bin_parser) init(data []byte, pfc *package_file_cache) {
	p.data = data
	p.version = -1            // unknown version
	p.strList = []string{""}  // empty string is mapped to 0
	p.pathList = []string{""} // empty string is mapped to 0
	p.pfc = pfc
}

func (p *gc_bin_parser) parse_export(callback func(string, ast.Decl)) {
	p.callback = callback

	// read version info
	var versionstr string
	if b := p.rawByte(); b == 'c' || b == 'd' {
		// Go1.7 encoding; first byte encodes low-level
		// encoding format (compact vs debug).
		// For backward-compatibility only (avoid problems with
		// old installed packages). Newly compiled packages use
		// the extensible format string.
		// TODO(gri) Remove this support eventually; after Go1.8.
		if b == 'd' {
			p.debugFormat = true
		}
		p.trackAllTypes = p.rawByte() == 'a'
		p.posInfoFormat = p.int() != 0
		versionstr = p.string()
		if versionstr == "v1" {
			p.version = 0
		}
	} else {
		// Go1.8 extensible encoding
		// read version string and extract version number (ignore anything after the version number)
		versionstr = p.rawStringln(b)
		if s := strings.SplitN(versionstr, " ", 3); len(s) >= 2 && s[0] == "version" {
			if v, err := strconv.Atoi(s[1]); err == nil && v > 0 {
				p.version = v
			}
		}
	}

	// read version specific flags - extend as necessary
	switch p.version {
	case 6, 5, 4, 3, 2, 1:
		p.debugFormat = p.rawStringln(p.rawByte()) == "debug"
		p.trackAllTypes = p.int() != 0
		p.posInfoFormat = p.int() != 0
	case 0:
		// Go1.7 encoding format - nothing to do here
	default:
		panic(fmt.Errorf("unknown export format version %d (%q)", p.version, versionstr))
	}

	// --- generic export data ---

	// populate typList with predeclared "known" types
	p.typList = append(p.typList, predeclared...)

	// read package data
	pkgName := p.pkg()
	p.pfc.defalias = pkgName[strings.LastIndex(pkgName, "!")+1:]

	// read objects of phase 1 only (see cmd/compiler/internal/gc/bexport.go)
	objcount := 0
	for {
		tag := p.tagOrIndex()
		if tag == endTag {
			break
		}
		p.obj(tag)
		objcount++
	}

	// self-verification
	if count := p.int(); count != objcount {
		panic(fmt.Sprintf("got %d objects; want %d", objcount, count))
	}
}

func (p *gc_bin_parser) pkg() string {
	// if the package was seen before, i is its index (>= 0)
	i := p.tagOrIndex()
	if i >= 0 {
		return p.pkgList[i]
	}

	// otherwise, i is the package tag (< 0)
	if i != packageTag {
		panic(fmt.Sprintf("unexpected package tag %d version %d", i, p.version))
	}

	// read package data
	name := p.string()
	var path string
	if p.version >= 5 {
		path = p.path()
	} else {
		path = p.string()
	}
	if p.version >= 6 {
		p.int() // package height; unused by go/types
	}

	// we should never see an empty package name
	if name == "" {
		panic("empty package name in import")
	}

	// an empty path denotes the package we are currently importing;
	// it must be the first package we see
	if (path == "") != (len(p.pkgList) == 0) {
		panic(fmt.Sprintf("package path %q for pkg index %d", path, len(p.pkgList)))
	}

	var fullName string
	if path != "" {
		fullName = "!" + path + "!" + name
		p.pfc.add_package_to_scope(fullName, path)
	} else {
		fullName = "!" + p.pfc.name + "!" + name
	}

	// if the package was imported before, use that one; otherwise create a new one
	p.pkgList = append(p.pkgList, fullName)
	return p.pkgList[len(p.pkgList)-1]
}

func (p *gc_bin_parser) obj(tag int) {
	switch tag {
	case constTag:
		p.pos()
		pkg, name := p.qualifiedName()
		typ := p.typ("")
		p.skipValue() // ignore const value, gocode's not interested
		p.callback(pkg, &ast.GenDecl{
			Tok: token.CONST,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names:  []*ast.Ident{ast.NewIdent(name)},
					Type:   typ,
					Values: []ast.Expr{&ast.BasicLit{Kind: token.INT, Value: "0"}},
				},
			},
		})

	case aliasTag:
		// TODO(gri) verify type alias hookup is correct
		p.pos()
		pkg, name := p.qualifiedName()
		typ := p.typ("")
		p.callback(pkg, &ast.GenDecl{
			Tok:   token.TYPE,
			Specs: []ast.Spec{typeAliasSpec(name, typ)},
		})

	case typeTag:
		_ = p.typ("")

	case varTag:
		p.pos()
		pkg, name := p.qualifiedName()
		typ := p.typ("")
		p.callback(pkg, &ast.GenDecl{
			Tok: token.VAR,
			Specs: []ast.Spec{
				&ast.ValueSpec{
					Names: []*ast.Ident{ast.NewIdent(name)},
					Type:  typ,
				},
			},
		})

	case funcTag:
		p.pos()
		pkg, name := p.qualifiedName()
		params := p.paramList()
		results := p.paramList()
		p.callback(pkg, &ast.FuncDecl{
			Name: ast.NewIdent(name),
			Type: &ast.FuncType{Params: params, Results: results},
		})

	default:
		panic(fmt.Sprintf("unexpected object tag %d", tag))
	}
}

const deltaNewFile = -64 // see cmd/compile/internal/gc/bexport.go

func (p *gc_bin_parser) pos() {
	if !p.posInfoFormat {
		return
	}

	file := p.prevFile
	line := p.prevLine
	delta := p.int()
	line += delta
	if p.version >= 5 {
		if delta == deltaNewFile {
			if n := p.int(); n >= 0 {
				// file changed
				file = p.path()
				line = n
			}
		}
	} else {
		if delta == 0 {
			if n := p.int(); n >= 0 {
				// file changed
				file = p.prevFile[:n] + p.string()
				line = p.int()
			}
		}
	}
	p.prevFile = file
	p.prevLine = line

	// TODO(gri) register new position
}

func (p *gc_bin_parser) qualifiedName() (pkg string, name string) {
	name = p.string()
	pkg = p.pkg()
	return pkg, name
}

func (p *gc_bin_parser) reserveMaybe() int {
	if p.trackAllTypes {
		p.typList = append(p.typList, nil)
		return len(p.typList) - 1
	} else {
		return -1
	}
}

func (p *gc_bin_parser) recordMaybe(idx int, t ast.Expr) ast.Expr {
	if idx == -1 {
		return t
	}
	p.typList[idx] = t
	return t
}

func (p *gc_bin_parser) record(t ast.Expr) {
	p.typList = append(p.typList, t)
}

// parent is the package which declared the type; parent == nil means
// the package currently imported. The parent package is needed for
// exported struct fields and interface methods which don't contain
// explicit package information in the export data.
func (p *gc_bin_parser) typ(parent string) ast.Expr {
	// if the type was seen before, i is its index (>= 0)
	i := p.tagOrIndex()
	if i >= 0 {
		return p.typList[i]
	}

	// otherwise, i is the type tag (< 0)
	switch i {
	case namedTag:
		// read type object
		p.pos()
		parent, name := p.qualifiedName()
		tdecl := &ast.GenDecl{
			Tok: token.TYPE,
			Specs: []ast.Spec{
				&ast.TypeSpec{
					Name: ast.NewIdent(name),
				},
			},
		}

		// record it right away (underlying type can contain refs to t)
		t := &ast.SelectorExpr{X: ast.NewIdent(parent), Sel: ast.NewIdent(name)}
		p.record(t)

		// parse underlying type
		t0 := p.typ(parent)
		tdecl.Specs[0].(*ast.TypeSpec).Type = t0

		p.callback(parent, tdecl)

		// interfaces have no methods
		if _, ok := t0.(*ast.InterfaceType); ok {
			return t
		}

		// read associated methods
		for i := p.int(); i > 0; i-- {
			// TODO(gri) replace this with something closer to fieldName
			p.pos()
			name := p.string()
			if !exported(name) {
				p.pkg()
			}

			recv := p.paramList()
			params := p.paramList()
			results := p.paramList()
			p.int() // go:nointerface pragma - discarded

			strip_method_receiver(recv)
			p.callback(parent, &ast.FuncDecl{
				Recv: recv,
				Name: ast.NewIdent(name),
				Type: &ast.FuncType{Params: params, Results: results},
			})
		}
		return t
	case arrayTag:
		i := p.reserveMaybe()
		n := p.int64()
		elt := p.typ(parent)
		return p.recordMaybe(i, &ast.ArrayType{
			Len: &ast.BasicLit{Kind: token.INT, Value: fmt.Sprint(n)},
			Elt: elt,
		})

	case sliceTag:
		i := p.reserveMaybe()
		elt := p.typ(parent)
		return p.recordMaybe(i, &ast.ArrayType{Len: nil, Elt: elt})

	case dddTag:
		i := p.reserveMaybe()
		elt := p.typ(parent)
		return p.recordMaybe(i, &ast.Ellipsis{Elt: elt})

	case structTag:
		i := p.reserveMaybe()
		return p.recordMaybe(i, p.structType(parent))

	case pointerTag:
		i := p.reserveMaybe()
		elt := p.typ(parent)
		return p.recordMaybe(i, &ast.StarExpr{X: elt})

	case signatureTag:
		i := p.reserveMaybe()
		params := p.paramList()
		results := p.paramList()
		return p.recordMaybe(i, &ast.FuncType{Params: params, Results: results})

	case interfaceTag:
		i := p.reserveMaybe()
		var embeddeds []*ast.SelectorExpr
		for n := p.int(); n > 0; n-- {
			p.pos()
			if named, ok := p.typ(parent).(*ast.SelectorExpr); ok {
				embeddeds = append(embeddeds, named)
			}
		}
		methods := p.methodList(parent)
		for _, field := range embeddeds {
			methods = append(methods, &ast.Field{Type: field})
		}
		return p.recordMaybe(i, &ast.InterfaceType{Methods: &ast.FieldList{List: methods}})

	case mapTag:
		i := p.reserveMaybe()
		key := p.typ(parent)
		val := p.typ(parent)
		return p.recordMaybe(i, &ast.MapType{Key: key, Value: val})

	case chanTag:
		i := p.reserveMaybe()
		dir := ast.SEND | ast.RECV
		switch d := p.int(); d {
		case 1:
			dir = ast.RECV
		case 2:
			dir = ast.SEND
		case 3:
			// already set
		default:
			panic(fmt.Sprintf("unexpected channel dir %d", d))
		}
		elt := p.typ(parent)
		return p.recordMaybe(i, &ast.ChanType{Dir: dir, Value: elt})

	default:
		panic(fmt.Sprintf("unexpected type tag %d", i))
	}
}

func (p *gc_bin_parser) structType(parent string) *ast.StructType {
	var fields []*ast.Field
	if n := p.int(); n > 0 {
		fields = make([]*ast.Field, n)
		for i := range fields {
			fields[i], _ = p.field(parent) // (*ast.Field, tag), not interested in tags
		}
	}
	return &ast.StructType{Fields: &ast.FieldList{List: fields}}
}

func (p *gc_bin_parser) field(parent string) (*ast.Field, string) {
	p.pos()
	_, name, _ := p.fieldName(parent)
	typ := p.typ(parent)
	tag := p.string()

	var names []*ast.Ident
	if name != "" {
		names = []*ast.Ident{ast.NewIdent(name)}
	}
	return &ast.Field{
		Names: names,
		Type:  typ,
	}, tag
}

func (p *gc_bin_parser) methodList(parent string) (methods []*ast.Field) {
	if n := p.int(); n > 0 {
		methods = make([]*ast.Field, n)
		for i := range methods {
			methods[i] = p.method(parent)
		}
	}
	return
}

func (p *gc_bin_parser) method(parent string) *ast.Field {
	p.pos()
	_, name, _ := p.fieldName(parent)
	params := p.paramList()
	results := p.paramList()
	return &ast.Field{
		Names: []*ast.Ident{ast.NewIdent(name)},
		Type:  &ast.FuncType{Params: params, Results: results},
	}
}

func (p *gc_bin_parser) fieldName(parent string) (string, string, bool) {
	name := p.string()
	pkg := parent
	if p.version == 0 && name == "_" {
		// version 0 didn't export a package for _ fields
		return pkg, name, false
	}
	var alias bool
	switch name {
	case "":
		// 1) field name matches base type name and is exported: nothing to do
	case "?":
		// 2) field name matches base type name and is not exported: need package
		name = ""
		pkg = p.pkg()
	case "@":
		// 3) field name doesn't match type name (alias)
		name = p.string()
		alias = true
		fallthrough
	default:
		if !exported(name) {
			pkg = p.pkg()
		}
	}
	return pkg, name, alias
}

func (p *gc_bin_parser) paramList() *ast.FieldList {
	n := p.int()
	if n == 0 {
		return nil
	}
	// negative length indicates unnamed parameters
	named := true
	if n < 0 {
		n = -n
		named = false
	}
	// n > 0
	flds := make([]*ast.Field, n)
	for i := range flds {
		flds[i] = p.param(named)
	}
	return &ast.FieldList{List: flds}
}

func (p *gc_bin_parser) param(named bool) *ast.Field {
	t := p.typ("")

	name := "?"
	if named {
		name = p.string()
		if name == "" {
			panic("expected named parameter")
		}
		if name != "_" {
			p.pkg()
		}
		if i := strings.Index(name, "·"); i > 0 {
			name = name[:i] // cut off gc-specific parameter numbering
		}
	}

	// read and discard compiler-specific info
	p.string()

	return &ast.Field{
		Names: []*ast.Ident{ast.NewIdent(name)},
		Type:  t,
	}
}

func exported(name string) bool {
	ch, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(ch)
}

func (p *gc_bin_parser) skipValue() {
	switch tag := p.tagOrIndex(); tag {
	case falseTag, trueTag:
	case int64Tag:
		p.int64()
	case floatTag:
		p.float()
	case complexTag:
		p.float()
		p.float()
	case stringTag:
		p.string()
	default:
		panic(fmt.Sprintf("unexpected value tag %d", tag))
	}
}

func (p *gc_bin_parser) float() {
	sign := p.int()
	if sign == 0 {
		return
	}

	p.int()    // exp
	p.string() // mant
}

// ----------------------------------------------------------------------------
// Low-level decoders

func (p *gc_bin_parser) tagOrIndex() int {
	if p.debugFormat {
		p.marker('t')
	}

	return int(p.rawInt64())
}

func (p *gc_bin_parser) int() int {
	x := p.int64()
	if int64(int(x)) != x {
		panic("exported integer too large")
	}
	return int(x)
}

func (p *gc_bin_parser) int64() int64 {
	if p.debugFormat {
		p.marker('i')
	}

	return p.rawInt64()
}

func (p *gc_bin_parser) path() string {
	if p.debugFormat {
		p.marker('p')
	}
	// if the path was seen before, i is its index (>= 0)
	// (the empty string is at index 0)
	i := p.rawInt64()
	if i >= 0 {
		return p.pathList[i]
	}
	// otherwise, i is the negative path length (< 0)
	a := make([]string, -i)
	for n := range a {
		a[n] = p.string()
	}
	s := strings.Join(a, "/")
	p.pathList = append(p.pathList, s)
	return s
}

func (p *gc_bin_parser) string() string {
	if p.debugFormat {
		p.marker('s')
	}
	// if the string was seen before, i is its index (>= 0)
	// (the empty string is at index 0)
	i := p.rawInt64()
	if i >= 0 {
		return p.strList[i]
	}
	// otherwise, i is the negative string length (< 0)
	if n := int(-i); n <= cap(p.buf) {
		p.buf = p.buf[:n]
	} else {
		p.buf = make([]byte, n)
	}
	for i := range p.buf {
		p.buf[i] = p.rawByte()
	}
	s := string(p.buf)
	p.strList = append(p.strList, s)
	return s
}

func (p *gc_bin_parser) marker(want byte) {
	if got := p.rawByte(); got != want {
		panic(fmt.Sprintf("incorrect marker: got %c; want %c (pos = %d)", got, want, p.read))
	}

	pos := p.read
	if n := int(p.rawInt64()); n != pos {
		panic(fmt.Sprintf("incorrect position: got %d; want %d", n, pos))
	}
}

// rawInt64 should only be used by low-level decoders.
func (p *gc_bin_parser) rawInt64() int64 {
	i, err := binary.ReadVarint(p)
	if err != nil {
		panic(fmt.Sprintf("read error: %v", err))
	}
	return i
}

// rawStringln should only be used to read the initial version string.
func (p *gc_bin_parser) rawStringln(b byte) string {
	p.buf = p.buf[:0]
	for b != '\n' {
		p.buf = append(p.buf, b)
		b = p.rawByte()
	}
	return string(p.buf)
}

// needed for binary.ReadVarint in rawInt64
func (p *gc_bin_parser) ReadByte() (byte, error) {
	return p.rawByte(), nil
}

// byte is the bottleneck interface for reading p.data.
// It unescapes '|' 'S' to '$' and '|' '|' to '|'.
// rawByte should only be used by low-level decoders.
func (p *gc_bin_parser) rawByte() byte {
	b := p.data[0]
	r := 1
	if b == '|' {
		b = p.data[1]
		r = 2
		switch b {
		case 'S':
			b = '$'
		case '|':
			// nothing to do
		default:
			panic("unexpected escape sequence in export data")
		}
	}
	p.data = p.data[r:]
	p.read += r
	return b

}

// ----------------------------------------------------------------------------
// Export format

// Tags. Must be < 0.
const (
	// Objects
	packageTag = -(iota + 1)
	constTag
	typeTag
	varTag
	funcTag
	endTag

	// Types
	namedTag
	arrayTag
	sliceTag
	dddTag
	structTag
	pointerTag
	signatureTag
	interfaceTag
	mapTag
	chanTag

	// Values
	falseTag
	trueTag
	int64Tag
	floatTag
	fractionTag // not used by gc
	complexTag
	stringTag
	nilTag     // only used by gc (appears in exported inlined function bodies)
	unknownTag // not used by gc (only appears in packages with errors)

	// Type aliases
	aliasTag
)

var predeclared = []ast.Expr{
	// basic types
	ast.NewIdent("bool"),
	ast.NewIdent("int"),
	ast.NewIdent("int8"),
	ast.NewIdent("int16"),
	ast.NewIdent("int32"),
	ast.NewIdent("int64"),
	ast.NewIdent("uint"),
	ast.NewIdent("uint8"),
	ast.NewIdent("uint16"),
	ast.NewIdent("uint32"),
	ast.NewIdent("uint64"),
	ast.NewIdent("uintptr"),
	ast.NewIdent("float32"),
	ast.NewIdent("float64"),
	ast.NewIdent("complex64"),
	ast.NewIdent("complex128"),
	ast.NewIdent("string"),

	// basic type aliases
	ast.NewIdent("byte"),
	ast.NewIdent("rune"),

	// error
	ast.NewIdent("error"),

	// TODO(nsf): don't think those are used in just package type info,
	// maybe for consts, but we are not interested in that
	// untyped types
	ast.NewIdent("&untypedBool&"),    // TODO: types.Typ[types.UntypedBool],
	ast.NewIdent("&untypedInt&"),     // TODO: types.Typ[types.UntypedInt],
	ast.NewIdent("&untypedRune&"),    // TODO: types.Typ[types.UntypedRune],
	ast.NewIdent("&untypedFloat&"),   // TODO: types.Typ[types.UntypedFloat],
	ast.NewIdent("&untypedComplex&"), // TODO: types.Typ[types.UntypedComplex],
	ast.NewIdent("&untypedString&"),  // TODO: types.Typ[types.UntypedString],
	ast.NewIdent("&untypedNil&"),     // TODO: types.Typ[types.UntypedNil],

	// package unsafe
	&ast.SelectorExpr{X: ast.NewIdent("unsafe"), Sel: ast.NewIdent("Pointer")},

	// invalid type
	ast.NewIdent(">_<"), // TODO: types.Typ[types.Invalid], // only appears in packages with errors

	// used internally by gc; never used by this package or in .a files
	ast.NewIdent("any"),
}

"""



```