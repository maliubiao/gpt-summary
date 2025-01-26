Response:
Let's break down the thought process to analyze the provided Go code snippet.

**1. Initial Scan and High-Level Understanding:**

The first thing I'd do is a quick skim of the code. I see:

* Package declaration: `package main` suggests this is an executable.
* Imports: `fmt`, `go/ast`, `go/parser`, `go/token`, `os`, `path/filepath`, `strings`. These strongly hint at code parsing and manipulation. `go/ast` and `go/parser` are the key indicators.
* Struct `tagParser`: This likely holds the state for the parsing process.
* Function `Parse`:  This looks like the main entry point for the parsing logic. It takes a filename, boolean flags, and a `FieldSet`.
* Several methods on `tagParser` starting with `parse`:  `parsePackage`, `parseImports`, `parseDeclarations`, etc. These clearly represent the different stages of parsing Go source code.
* Mentions of `Tag`, `TagType`, and `FieldSet`:  These are likely custom types defined elsewhere in the project, probably representing the output of the parsing process.

**2. Core Functionality Hypothesis:**

Based on the imports and the names of the functions and types, the core functionality seems to be parsing Go source code and extracting information about its structure. This information is then likely used to create "tags" representing different code elements (packages, imports, functions, types, etc.). The `relative` and `basepath` parameters suggest handling file paths, possibly for generating tags in a specific format.

**3. Deeper Dive into Key Functions:**

* **`Parse` function:** This initializes the `tagParser`, calls `parser.ParseFile` to actually parse the Go source, and then calls other `parse...` methods to extract specific information. This confirms the initial hypothesis.
* **`parsePackage`:**  Clearly extracts the package name.
* **`parseImports`:** Extracts import paths.
* **`parseDeclarations`:**  This is more complex. It iterates through declarations (`ast.Decl`) and distinguishes between type declarations (`ast.GenDecl` with `ast.TypeSpec`), value declarations (`ast.GenDecl` with `ast.ValueSpec`), and function declarations (`ast.FuncDecl`). This confirms the code's ability to identify different kinds of Go code elements.
* **`parseFunction`:**  Extracts function names, parameters, return types, and handles methods (functions with receivers). The logic around `extraSymbols` suggests adding additional tag entries with fully qualified names.
* **`parseTypeDeclaration`:** Handles structs and interfaces, extracting fields and methods.
* **`parseValueDeclaration`:** Extracts variable and constant names and types.
* **`createTag`:**  This function is responsible for creating the `Tag` object with relevant information (name, filename, line number, type). The logic for relative paths is handled here.

**4. Inferring the Go Language Feature:**

The overall purpose of the code strongly suggests it's implementing a *tag generation* tool for Go code. These tags are likely used by editors or other tools for features like "go to definition," symbol browsing, and code navigation. Tools like `ctags` or `etags` provide similar functionality for various programming languages.

**5. Code Example for Illustration:**

To demonstrate the functionality, I'd create a simple Go file and imagine how this parser would process it:

```go
// Input: example.go
package main

import "fmt"

type MyInt int

func Add(a, b int) int {
	return a + b
}

func (m MyInt) String() string {
	return fmt.Sprintf("MyInt: %d", m)
}

var count int = 0
const PI = 3.14
```

Then, I'd manually trace the `Parse` function's execution, imagining the values of `p.tags` after each `parse...` call. This would help me formulate the "Expected Output."

**6. Command-Line Argument Considerations:**

The `Parse` function takes `relative` and `basepath` as arguments. Since this snippet is likely part of a larger command-line tool, I'd speculate on how these arguments are used. `relative` likely controls whether the generated tag file uses relative or absolute paths, and `basepath` would be the directory used for calculating relative paths.

**7. Potential Pitfalls:**

I'd look for areas where users might make mistakes when *using* a tool built with this parser. For example, providing an incorrect `basepath` would lead to incorrect relative paths in the tag file. Also, the behavior of `extraSymbols` might not be immediately obvious to the user.

**8. Structuring the Answer:**

Finally, I'd organize my findings into a clear and structured answer, addressing each point raised in the prompt:

* **Functionality:** Summarize the core purpose.
* **Go Feature:** Explicitly state that it's likely a tag generator.
* **Code Example:** Provide the input and expected output to illustrate the parsing.
* **Command-Line Arguments:** Explain the purpose of `relative` and `basepath`.
* **Potential Pitfalls:**  Highlight common mistakes users might make.

This systematic approach, starting with a high-level overview and gradually delving into the details, allows for a comprehensive understanding and accurate description of the provided Go code.
这段Go语言代码是用于解析Go源代码文件并提取代码元素的元数据，最终生成一种“标签(tag)”信息。这种标签信息通常被代码编辑器、IDE或其他代码分析工具使用，以实现诸如“跳转到定义”、“符号查找”等功能。

以下是代码的功能分解：

**核心功能:**

1. **解析Go源代码:** 使用 `go/parser` 包来解析给定的Go源代码文件。
2. **提取代码元素信息:**  识别并提取各种Go语言结构的信息，包括：
    * **包(Package):**  提取包名。
    * **导入(Import):**  提取导入的包路径。
    * **类型(Type):** 提取类型定义（如 `struct`, `interface`, 自定义类型）及其相关信息（如结构体字段，接口方法）。
    * **函数(Function):** 提取函数名、参数、返回值、所属的接收者（如果存在）。
    * **方法(Method):**  提取方法名、接收者类型、参数、返回值。
    * **变量(Variable):** 提取变量名和类型。
    * **常量(Constant):** 提取常量名和类型。
    * **结构体字段(Field):** 提取结构体字段名和类型。
    * **嵌入字段(Embedded):** 提取嵌入字段的类型。
3. **生成标签(Tag):**  将提取到的信息组织成 `Tag` 结构体。每个 `Tag` 包含代码元素的名称、所在文件名、行号以及类型等信息。
4. **处理文件名:**  可以根据 `relative` 和 `basepath` 参数，决定标签中使用的文件名是相对于 `basepath` 的相对路径，还是绝对路径。
5. **支持额外的符号:**  通过 `extraSymbols` 参数，可以控制是否为函数和方法生成包含包名和接收者类型的额外标签。

**推断的Go语言功能实现: 代码标签生成器 (Code Tag Generator)**

这段代码很可能是一个Go语言代码标签生成器的一部分，类似于 `ctags` 或 `etags` 这样的工具。 它可以扫描Go源代码，并生成一个包含各种代码元素索引的文件。编辑器或IDE可以读取这个标签文件，从而实现快速的代码导航和符号查找。

**Go代码举例说明:**

假设有以下Go源代码文件 `example.go`:

```go
// example.go
package mypackage

import "fmt"

// MyInt is a custom integer type.
type MyInt int

// Add adds two integers.
func Add(a, b int) int {
	return a + b
}

// String implements the Stringer interface for MyInt.
func (m MyInt) String() string {
	return fmt.Sprintf("MyInt: %d", m)
}

// globalVar is a global variable.
var globalVar string = "hello"

// PI is a constant.
const PI = 3.14159

type MyStruct struct {
	Name string
	Age  int
}

func (ms *MyStruct) Greet() {
	fmt.Println("Hello, my name is", ms.Name)
}

type MyInterface interface {
	DoSomething()
}
```

**假设的输入与输出:**

如果我们使用 `Parse` 函数解析 `example.go`，并假设 `relative` 为 `false`，`basepath` 为空，`extraSymbols` 包含 `ExtraTags`， 那么预期的输出 `p.tags` (一个 `Tag` 类型的切片) 可能会包含类似以下的元素：

```
[
  {Name: "mypackage", Filename: "example.go", Line: 2, Type: "p"}, // 包
  {Name: "fmt", Filename: "example.go", Line: 4, Type: "i"},       // 导入
  {Name: "MyInt", Filename: "example.go", Line: 7, Type: "t"},     // 类型
  {Name: "mypackage.MyInt", Filename: "example.go", Line: 7, Type: "t"}, // 额外的类型标签
  {Name: "Add", Filename: "example.go", Line: 10, Type: "f", Fields: map[string]string{"access": "public", "signature": "(a int, b int)", "type": "int"}}, // 函数
  {Name: "mypackage.Add", Filename: "example.go", Line: 10, Type: "f", Fields: map[string]string{"access": "public", "signature": "(a int, b int)", "type": "int"}}, // 额外的函数标签
  {Name: "String", Filename: "example.go", Line: 15, Type: "m", Fields: map[string]string{"access": "public", "signature": "()", "type": "string", "receiver": "MyInt"}}, // 方法
  {Name: "MyInt.String", Filename: "example.go", Line: 15, Type: "m", Fields: map[string]string{"access": "public", "signature": "()", "type": "string", "receiver": "MyInt"}}, // 额外的方法标签
  {Name: "mypackage.MyInt.String", Filename: "example.go", Line: 15, Type: "m", Fields: map[string]string{"access": "public", "signature": "()", "type": "string", "receiver": "MyInt"}}, // 额外的方法标签
  {Name: "globalVar", Filename: "example.go", Line: 20, Type: "v", Fields: map[string]string{"access": "private", "type": "string"}}, // 变量
  {Name: "mypackage.globalVar", Filename: "example.go", Line: 20, Type: "v", Fields: map[string]string{"access": "private", "type": "string"}}, // 额外的变量标签
  {Name: "PI", Filename: "example.go", Line: 23, Type: "c", Fields: map[string]string{"access": "public", "type": "float64"}}, // 常量
  {Name: "mypackage.PI", Filename: "example.go", Line: 23, Type: "c", Fields: map[string]string{"access": "public", "type": "float64"}}, // 额外的常量标签
  {Name: "MyStruct", Filename: "example.go", Line: 25, Type: "t", Fields: map[string]string{"access": "public", "type": "struct"}}, // 类型
  {Name: "mypackage.MyStruct", Filename: "example.go", Line: 25, Type: "t"}, // 额外的类型标签
  {Name: "Name", Filename: "example.go", Line: 26, Type: "m", Fields: map[string]string{"access": "public", "receiver": "MyStruct", "type": "string"}}, // 结构体字段
  {Name: "Age", Filename: "example.go", Line: 27, Type: "m", Fields: map[string]string{"access": "public", "receiver": "MyStruct", "type": "int"}},    // 结构体字段
  {Name: "Greet", Filename: "example.go", Line: 30, Type: "m", Fields: map[string]string{"access": "public", "signature": "()", "type": "", "receiver": "*MyStruct"}}, // 方法
  {Name: "*MyStruct.Greet", Filename: "example.go", Line: 30, Type: "m", Fields: map[string]string{"access": "public", "signature": "()", "type": "", "receiver": "*MyStruct"}}, // 额外的方法标签
  {Name: "mypackage.*MyStruct.Greet", Filename: "example.go", Line: 30, Type: "m", Fields: map[string]string{"access": "public", "signature": "()", "type": "", "receiver": "*MyStruct"}}, // 额外的方法标签
  {Name: "MyInterface", Filename: "example.go", Line: 34, Type: "i", Fields: map[string]string{"access": "public", "type": "interface"}}, // 接口
]
```

**命令行参数的具体处理:**

`Parse` 函数本身不是一个命令行程序，但它很可能被一个命令行工具调用。该工具可能会处理如下命令行参数：

* **`filename`:**  要解析的Go源代码文件的路径。这是一个必需的参数。
* **`--relative`:**  一个布尔标志，用于指定生成的标签中的文件名是否相对于 `basepath`。如果设置，则为 `true`，否则为 `false`。
* **`--basepath`:**  一个字符串，指定计算相对路径的基准目录。只有当 `--relative` 设置为 `true` 时才有效。
* **`--extra`:**  可能对应于 `FieldSet` 类型的 `extraSymbols` 参数，用于控制是否生成额外的符号标签。可能接受类似 "receiver", "package" 或 "all" 这样的值。

**例如，一个可能的命令行调用可能是:**

```bash
gotags --relative --basepath /path/to/project example.go
```

这个命令会解析 `example.go` 文件，并生成标签，其中文件名是相对于 `/path/to/project` 的相对路径。

**使用者易犯错的点:**

1. **`basepath` 设置不正确:**  如果使用了 `--relative` 选项，但 `--basepath` 没有设置为项目根目录或其他合适的目录，生成的标签中的相对路径可能会不正确，导致编辑器无法正确跳转。例如，如果用户在项目子目录中执行命令，但 `--basepath` 指向了其他位置。

   **错误示例:**

   假设项目结构如下：

   ```
   project/
   ├── main.go
   └── utils/
       └── helper.go
   ```

   如果在 `project/utils/` 目录下执行 `gotags --relative --basepath /tmp main.go`，由于 `basepath` 设置为 `/tmp`，生成的 `main.go` 的标签路径将会是错误的。

2. **不理解 `extraSymbols` 的作用:**  用户可能不清楚 `extraSymbols` 参数会生成额外的标签，导致标签文件中出现重复或冗余的条目，虽然这通常不会导致错误，但可能会使标签文件变大。

3. **文件路径问题:**  直接调用 `Parse` 函数时，如果没有正确处理绝对路径和相对路径，可能会导致文件找不到的错误。

总而言之，这段代码实现了一个Go语言代码的解析器，其主要功能是提取代码元素的元数据并生成标签。这通常是构建代码导航和索引工具的关键部分。用户在使用基于此代码构建的工具时，需要注意命令行参数的正确设置，特别是涉及到文件路径和相对路径时。

Prompt: 
```
这是路径为go/src/github.com/jstemmer/gotags/parser.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// tagParser contains the data needed while parsing.
type tagParser struct {
	fset         *token.FileSet
	tags         []Tag    // list of created tags
	types        []string // all types we encounter, used to determine the constructors
	relative     bool     // should filenames be relative to basepath
	basepath     string   // output file directory
	extraSymbols FieldSet // add the receiver and the package to function and method name
}

// Parse parses the source in filename and returns a list of tags. If relative
// is true, the filenames in the list of tags are relative to basepath.
func Parse(filename string, relative bool, basepath string, extra FieldSet) ([]Tag, error) {
	p := &tagParser{
		fset:         token.NewFileSet(),
		tags:         []Tag{},
		types:        make([]string, 0),
		relative:     relative,
		basepath:     basepath,
		extraSymbols: extra,
	}

	f, err := parser.ParseFile(p.fset, filename, nil, 0)
	if err != nil {
		return nil, err
	}

	// package
	pkgName := p.parsePackage(f)

	// imports
	p.parseImports(f)

	// declarations
	p.parseDeclarations(f, pkgName)

	return p.tags, nil
}

// parsePackage creates a package tag.
func (p *tagParser) parsePackage(f *ast.File) string {
	p.tags = append(p.tags, p.createTag(f.Name.Name, f.Name.Pos(), Package))
	return f.Name.Name
}

// parseImports creates an import tag for each import.
func (p *tagParser) parseImports(f *ast.File) {
	for _, im := range f.Imports {
		name := strings.Trim(im.Path.Value, "\"")
		p.tags = append(p.tags, p.createTag(name, im.Path.Pos(), Import))
	}
}

// parseDeclarations creates a tag for each function, type or value declaration.
// On function symbol we will add 2 entries in the tag file, one with the function name only
// and one with the belonging module name and the function name.
// For method symbol we will add 3 entries: method, receiver.method, module.receiver.method
func (p *tagParser) parseDeclarations(f *ast.File, pkgName string) {
	// first parse the type and value declarations, so that we have a list of all
	// known types before parsing the functions.
	for _, d := range f.Decls {
		if decl, ok := d.(*ast.GenDecl); ok {
			for _, s := range decl.Specs {
				switch ts := s.(type) {
				case *ast.TypeSpec:
					p.parseTypeDeclaration(ts, pkgName)
				case *ast.ValueSpec:
					p.parseValueDeclaration(ts, pkgName)
				}
			}
		}
	}

	// now parse all the functions
	for _, d := range f.Decls {
		if decl, ok := d.(*ast.FuncDecl); ok {
			p.parseFunction(decl, pkgName)
		}
	}
}

// parseFunction creates a tag for function declaration f.
func (p *tagParser) parseFunction(f *ast.FuncDecl, pkgName string) {
	tag := p.createTag(f.Name.Name, f.Pos(), Function)

	tag.Fields[Access] = getAccess(tag.Name)
	tag.Fields[Signature] = fmt.Sprintf("(%s)", getTypes(f.Type.Params, true))
	tag.Fields[TypeField] = getTypes(f.Type.Results, false)

	if f.Recv != nil && len(f.Recv.List) > 0 {
		// this function has a receiver, set the type to Method
		tag.Fields[ReceiverType] = getType(f.Recv.List[0].Type, false)
		tag.Type = Method
	} else if name, ok := p.belongsToReceiver(f.Type.Results); ok {
		// this function does not have a receiver, but it belongs to one based
		// on its return values; its type will be Function instead of Method.
		tag.Fields[ReceiverType] = name
		tag.Type = Function
	}

	p.tags = append(p.tags, tag)

	if p.extraSymbols.Includes(ExtraTags) {
		allNames := make([]string, 0, 10)
		allNames = append(allNames, fmt.Sprintf("%s.%s", pkgName, f.Name.Name))
		if tag.Type == Method {
			allNames = append(allNames,
				fmt.Sprintf("%s.%s", tag.Fields[ReceiverType], f.Name.Name))
			allNames = append(allNames,
				fmt.Sprintf("%s.%s.%s",
					pkgName, tag.Fields[ReceiverType], f.Name.Name))
		}

		for _, n := range allNames {
			newTag := tag
			newTag.Name = n
			p.tags = append(p.tags, newTag)
		}
	}
}

// parseTypeDeclaration creates a tag for type declaration ts and for each
// field in case of a struct, or each method in case of an interface.
// The pkgName argument holds the name of the package the file currently parsed belongs to.
func (p *tagParser) parseTypeDeclaration(ts *ast.TypeSpec, pkgName string) {
	tag := p.createTag(ts.Name.Name, ts.Pos(), Type)

	tag.Fields[Access] = getAccess(tag.Name)

	switch s := ts.Type.(type) {
	case *ast.StructType:
		tag.Fields[TypeField] = "struct"
		p.parseStructFields(tag.Name, s)
		p.types = append(p.types, tag.Name)
	case *ast.InterfaceType:
		tag.Fields[TypeField] = "interface"
		tag.Type = Interface
		p.parseInterfaceMethods(tag.Name, s)
	default:
		tag.Fields[TypeField] = getType(ts.Type, true)
	}

	p.tags = append(p.tags, tag)

	if p.extraSymbols.Includes(ExtraTags) {
		extraTag := tag
		extraTag.Name = fmt.Sprintf("%s.%s", pkgName, tag.Name)
		p.tags = append(p.tags, extraTag)
	}
}

// parseValueDeclaration creates a tag for each variable or constant declaration,
// unless the declaration uses a blank identifier.
func (p *tagParser) parseValueDeclaration(v *ast.ValueSpec, pkgName string) {
	for _, d := range v.Names {
		if d.Name == "_" {
			continue
		}

		tag := p.createTag(d.Name, d.Pos(), Variable)
		tag.Fields[Access] = getAccess(tag.Name)

		if v.Type != nil {
			tag.Fields[TypeField] = getType(v.Type, true)
		}

		switch d.Obj.Kind {
		case ast.Var:
			tag.Type = Variable
		case ast.Con:
			tag.Type = Constant
		}
		p.tags = append(p.tags, tag)
		if p.extraSymbols.Includes(ExtraTags) {
			otherTag := tag
			otherTag.Name = fmt.Sprintf("%s.%s", pkgName, tag.Name)
			p.tags = append(p.tags, otherTag)
		}
	}
}

// parseStructFields creates a tag for each field in struct s, using name as the
// tags ctype.
func (p *tagParser) parseStructFields(name string, s *ast.StructType) {
	for _, f := range s.Fields.List {
		var tag Tag
		if len(f.Names) > 0 {
			for _, n := range f.Names {
				tag = p.createTag(n.Name, n.Pos(), Field)
				tag.Fields[Access] = getAccess(tag.Name)
				tag.Fields[ReceiverType] = name
				tag.Fields[TypeField] = getType(f.Type, true)
				p.tags = append(p.tags, tag)
			}
		} else {
			// embedded field
			tag = p.createTag(getType(f.Type, true), f.Pos(), Embedded)
			tag.Fields[Access] = getAccess(tag.Name)
			tag.Fields[ReceiverType] = name
			tag.Fields[TypeField] = getType(f.Type, true)
			p.tags = append(p.tags, tag)
		}
	}
}

// parseInterfaceMethods creates a tag for each method in interface s, using name
// as the tags ctype.
func (p *tagParser) parseInterfaceMethods(name string, s *ast.InterfaceType) {
	for _, f := range s.Methods.List {
		var tag Tag
		if len(f.Names) > 0 {
			tag = p.createTag(f.Names[0].Name, f.Names[0].Pos(), Method)
		} else {
			// embedded interface
			tag = p.createTag(getType(f.Type, true), f.Pos(), Embedded)
		}

		tag.Fields[Access] = getAccess(tag.Name)

		if t, ok := f.Type.(*ast.FuncType); ok {
			tag.Fields[Signature] = fmt.Sprintf("(%s)", getTypes(t.Params, true))
			tag.Fields[TypeField] = getTypes(t.Results, false)
		}

		tag.Fields[InterfaceType] = name

		p.tags = append(p.tags, tag)
	}
}

// createTag creates a new tag, using pos to find the filename and set the line number.
func (p *tagParser) createTag(name string, pos token.Pos, tagType TagType) Tag {
	f := p.fset.File(pos).Name()
	if p.relative {
		if abs, err := filepath.Abs(f); err != nil {
			fmt.Fprintf(os.Stderr, "could not determine absolute path: %s\n", err)
		} else if rel, err := filepath.Rel(p.basepath, abs); err != nil {
			fmt.Fprintf(os.Stderr, "could not determine relative path: %s\n", err)
		} else {
			f = rel
		}
	}
	return NewTag(name, f, p.fset.Position(pos).Line, tagType)
}

// belongsToReceiver checks if a function with these return types belongs to
// a receiver. If it belongs to a receiver, the name of that receiver will be
// returned with ok set to true. Otherwise ok will be false.
// Behavior should be similar to how go doc decides when a function belongs to
// a receiver (gosrc/pkg/go/doc/reader.go).
func (p *tagParser) belongsToReceiver(types *ast.FieldList) (name string, ok bool) {
	if types == nil || types.NumFields() == 0 {
		return "", false
	}

	// If the first return type has more than 1 result associated with
	// it, it should not belong to that receiver.
	// Similar behavior as go doc (go source/.
	if len(types.List[0].Names) > 1 {
		return "", false
	}

	// get name of the first return type
	t := getType(types.List[0].Type, false)

	// check if it exists in the current list of known types
	for _, knownType := range p.types {
		if t == knownType {
			return knownType, true
		}
	}

	return "", false
}

// getTypes returns a comma separated list of types in fields. If includeNames is
// true each type is preceded by a comma separated list of parameter names.
func getTypes(fields *ast.FieldList, includeNames bool) string {
	if fields == nil {
		return ""
	}

	types := make([]string, len(fields.List))
	for i, param := range fields.List {
		if len(param.Names) > 0 {
			// there are named parameters, there may be multiple names for a single type
			t := getType(param.Type, true)

			if includeNames {
				// join all the names, followed by their type
				names := make([]string, len(param.Names))
				for j, n := range param.Names {
					names[j] = n.Name
				}
				t = fmt.Sprintf("%s %s", strings.Join(names, ", "), t)
			} else {
				if len(param.Names) > 1 {
					// repeat t len(param.Names) times
					t = strings.Repeat(fmt.Sprintf("%s, ", t), len(param.Names))

					// remove trailing comma and space
					t = t[:len(t)-2]
				}
			}

			types[i] = t
		} else {
			// no named parameters
			types[i] = getType(param.Type, true)
		}
	}

	return strings.Join(types, ", ")
}

// getType returns a string representation of the type of node. If star is true and the
// type is a pointer, a * will be prepended to the string.
func getType(node ast.Node, star bool) (paramType string) {
	switch t := node.(type) {
	case *ast.Ident:
		paramType = t.Name
	case *ast.StarExpr:
		if star {
			paramType = "*" + getType(t.X, star)
		} else {
			paramType = getType(t.X, star)
		}
	case *ast.SelectorExpr:
		paramType = getType(t.X, star) + "." + getType(t.Sel, star)
	case *ast.ArrayType:
		if l, ok := t.Len.(*ast.BasicLit); ok {
			paramType = fmt.Sprintf("[%s]%s", l.Value, getType(t.Elt, star))
		} else {
			paramType = "[]" + getType(t.Elt, star)
		}
	case *ast.FuncType:
		fparams := getTypes(t.Params, true)
		fresult := getTypes(t.Results, false)

		if len(fresult) > 0 {
			paramType = fmt.Sprintf("func(%s) %s", fparams, fresult)
		} else {
			paramType = fmt.Sprintf("func(%s)", fparams)
		}
	case *ast.MapType:
		paramType = fmt.Sprintf("map[%s]%s", getType(t.Key, true), getType(t.Value, true))
	case *ast.ChanType:
		paramType = fmt.Sprintf("chan %s", getType(t.Value, true))
	case *ast.InterfaceType:
		paramType = "interface{}"
	case *ast.Ellipsis:
		paramType = fmt.Sprintf("...%s", getType(t.Elt, true))
	}
	return
}

// getAccess returns the string "public" if name is considered an exported name, otherwise
// the string "private" is returned.
func getAccess(name string) (access string) {
	if idx := strings.LastIndex(name, "."); idx > -1 && idx < len(name) {
		name = name[idx+1:]
	}

	if ast.IsExported(name) {
		access = "public"
	} else {
		access = "private"
	}
	return
}

"""



```