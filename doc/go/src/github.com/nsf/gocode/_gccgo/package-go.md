Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Scan and Keyword Identification:**

The first step is a quick scan for familiar Go keywords and package names. We see:

* `package main`:  Indicates an executable program, but given the filename (`package.go`) and path (`_gccgo`), it's likely a utility or internal part of a larger system.
* `import`:  `debug/elf`, `text/scanner`, `bytes`, `errors`, `io`, `fmt`, `strconv`, `go/ast`, `go/token`, `strings`. These immediately suggest the code is dealing with parsing, potentially analyzing Go code or related data. `debug/elf` is a strong indicator that it's processing compiled Go artifacts.
* `var builtin_type_names`: This looks like a pre-defined list of Go's built-in types.
* `func read_import_data`: The name suggests reading data related to imports.
* `func parse_import_data`:  This strongly indicates parsing the data read by the previous function.
* Types like `import_data_parser`, `import_data_type`:  These are custom types, confirming the data being processed has a specific structure.
* Helper functions like `expect`, `expect_ident`, `read_type`, `read_struct_type`, etc.: These strongly suggest a recursive descent parser.

**2. Understanding `read_import_data`:**

This function is relatively straightforward. It attempts to open an ELF file (identified by adding `.gox` to the `import_path`). It then looks for a specific section named `.go_export`. This section likely contains metadata about the exported symbols and types of the imported package.

**3. Deep Dive into `parse_import_data`:**

This is the core of the code. The function creates an `import_data_parser` and initializes it with the data read from the ELF file. The sequence of `p.expect_ident` and `p.expect` calls reveals the structure of the imported data:

* `"v1"`: Likely a version marker for the import data format.
* `"package"`, package identifier, `"pkgpath"`, package path, `"priority"`:  Basic package information.
* `"import"` loops:  Information about dependencies of the imported package.
* `"init"`: Information about initialization functions.
* A loop with cases `"const"`, `"type"`, `"var"`, `"func"`:  This strongly suggests parsing declarations of constants, types, variables, and functions.
* `"checksum"`:  A marker for the end of the declarations.

**4. Analyzing the `import_data_parser` Type and its Methods:**

The `import_data_parser` type encapsulates the parsing state. Its methods (`init`, `next`, `token`, `expect`, `read_type`, etc.) implement the logic for consuming tokens and extracting information from the input data stream. The `typetable` is a crucial element, acting as a symbol table to store and reference parsed type information, allowing for forward and backward references.

**5. Connecting the Dots - The "Why":**

The combination of reading from ELF files and parsing data that represents Go language constructs (types, functions, etc.) strongly points to this code being part of a tool that needs to understand the structure of compiled Go packages. Given the `_gccgo` in the path, it's highly likely this code is related to `gccgo`, an alternative Go compiler.

**6. Formulating the Explanation:**

Based on the analysis, the core functionality is parsing import metadata from compiled Go packages (`.gox` files). This metadata describes the exported types, constants, variables, and functions of a package. This information is likely used for code completion, type checking, or other static analysis tasks within the `gocode` tool.

**7. Crafting the Go Example:**

To illustrate the functionality, we need to demonstrate how the parser handles different Go language constructs. Examples for basic types, structs, interfaces, functions, and constants are appropriate. The key is to show how the *structure* of the Go code would be represented in the import data format (even though we don't know the exact format).

**8. Inferring Command-Line Arguments (Though Not Explicit):**

While the code itself doesn't show command-line argument parsing, the function `read_import_data("io")` suggests that the `import_path` is a key piece of information. In a real-world scenario, this path would likely come from command-line arguments or configuration.

**9. Identifying Potential Pitfalls:**

The parser is relatively complex, and there are several places where errors could occur:

* Incorrectly formatted `.gox` files.
* Version mismatches between the parser and the `.gox` format.
* Handling of complex type declarations.

**10. Structuring the Answer:**

Finally, the answer should be structured logically, covering the identified functionalities, providing a clear explanation of the inferred purpose, demonstrating with Go code examples, discussing command-line arguments (even if inferred), and highlighting potential pitfalls. Using clear and concise language is important.
这段代码是 Go 语言 `gocode` 工具中用于解析和理解 Go 语言包导入数据的一部分，尤其针对使用 `gccgo` 编译器编译的包。它的主要功能是读取并解析由 `gccgo` 编译器生成的 `.gox` 文件中的导出信息。

**核心功能:**

1. **读取导入数据 (`read_import_data` 函数):**
   - 该函数接收一个导入路径 (`import_path`) 作为参数，例如 "fmt"。
   - 它尝试打开与该导入路径对应的 `.gox` 文件，例如 "fmt.gox"。
   - `.gox` 文件是由 `gccgo` 编译器生成的，包含了该包导出的类型、常量、变量、函数等信息。
   - 它从 ELF 文件的 `.go_export` 节（section）中读取二进制数据。这个节包含了被导入包的元数据。

2. **解析导入数据 (`parse_import_data` 函数):**
   - 该函数接收从 `.gox` 文件读取的字节数组 (`data`) 作为参数。
   - 它使用 `import_data_parser` 结构体来解析这些二进制数据。
   - 解析过程包括：
     - 校验魔数 "v1"。
     - 读取包的标识符（package ident）、包路径（package path）和优先级（priority）。
     - 读取当前包依赖的其他包的导入信息。
     - 读取包的初始化函数信息。
     - 循环读取包中导出的常量 (`const`)、类型声明 (`type`)、变量 (`var`) 和函数 (`func`) 的信息。
     - 读取校验和 (`checksum`)，表示解析结束。

3. **类型解析 (`read_type`, `read_struct_type`, `read_interface_type` 等函数):**
   - 代码中包含一系列 `read_` 开头的函数，用于解析各种 Go 语言类型，例如结构体、接口、Map、Chan、数组、切片、函数类型等。
   - 这些函数根据 `.gox` 文件中的特定格式，将类型信息解析成 Go 语言的 `ast.Expr` 类型的抽象语法树节点。

4. **符号解析 (`read_const`, `read_var`, `read_func` 函数):**
   - 这些函数用于解析导出的常量、变量和函数的信息。
   - 它们会读取符号的名称和类型，并将类型信息通过 `read_type` 系列函数进行解析。

5. **格式化输出 (`pretty_print_type_expr` 函数):**
   - 该函数用于将 `ast.Expr` 类型的类型表达式格式化成易于阅读的字符串形式。这主要用于调试和输出解析结果。

**它是什么 Go 语言功能的实现？**

这段代码是 `gocode` 工具为了支持 `gccgo` 编译器而实现的**包信息提取**功能。`gocode` 是一个 Go 语言的代码自动补全工具，它需要理解项目中所有依赖包的导出符号信息才能提供准确的补全建议。由于 `gccgo` 编译器生成的包信息格式与标准 `go` 编译器不同，因此 `gocode` 需要专门的代码来解析 `gccgo` 生成的 `.gox` 文件。

**Go 代码举例说明:**

假设我们有一个名为 `mypackage` 的 Go 包，其源码如下：

```go
// mypackage/mypackage.go
package mypackage

const MyConstant = 10

type MyStruct struct {
	Field1 int
	Field2 string
}

func MyFunction(a int) string {
	return "Hello"
}
```

使用 `gccgo` 编译后，会生成一个 `mypackage.gox` 文件（或者包含 `.go_export` 节的 ELF 文件）。 `go/src/github.com/nsf/gocode/_gccgo/package.go` 中的代码就是用来解析 `mypackage.gox` 文件中关于 `MyConstant`, `MyStruct`, `MyFunction` 这些导出符号的信息的。

**假设的输入与输出:**

假设 `mypackage.gox` 文件的 `.go_export` 节包含以下（简化的、人为构造的）数据：

```
v1;package mypackage;pkgpath mypackage;priority 0;
type <0> "MyStruct" struct { Field1 <1> int; Field2 <2> string; };
func ( <?> *mypackage.MyStruct )  Method1() ;
const MyConstant = 10;
var MyVariable <3> int;
func MyFunction ( a <4> int ) <5> string ;
checksum ...;
```

**假设 `read_import_data("mypackage")` 读取到上述数据。`parse_import_data` 函数解析后可能的输出（通过 `println` 语句）：**

```
package ident: mypackage
package path: mypackage
package priority: 0
type MyStruct struct { Field1 int; Field2 string; }
func (*mypackage.MyStruct) Method1() 
const MyConstant
var MyVariable int
func MyFunction(a int) string
```

**命令行参数的具体处理:**

这段代码本身没有直接处理命令行参数。`read_import_data` 函数接收的 `import_path` 参数通常是由 `gocode` 的其他部分处理命令行参数或配置信息后传递进来的。例如，当用户在编辑器中输入 `mypackage.` 并触发自动补全时，`gocode` 会根据当前的上下文推断出需要导入 `mypackage`，然后调用 `read_import_data("mypackage")`。

**使用者易犯错的点:**

对于 `gocode` 的使用者来说，直接与这段代码交互的可能性很小。这个文件是 `gocode` 内部实现的一部分。然而，一些可能导致 `gocode` 无法正常工作，并可能与此代码相关的错误点包括：

1. **`gccgo` 编译的包信息缺失或损坏:** 如果 `.gox` 文件不存在，或者 `.go_export` 节损坏，`read_import_data` 函数会返回错误，导致 `gocode` 无法获取该包的补全信息。例如，如果 `mypackage.gox` 文件被意外删除，`gocode` 在尝试补全 `mypackage` 中的符号时就会失败。

2. **`gocode` 配置不正确:**  `gocode` 需要正确配置才能找到 `gccgo` 编译的包。如果 `GOROOT` 或 `GOPATH` 设置不当，`gocode` 可能找不到 `.gox` 文件。

3. **`gccgo` 版本不兼容:**  如果使用的 `gccgo` 版本生成的 `.gox` 文件格式与 `gocode` 中解析代码所期望的格式不一致，解析过程可能会出错。

**总结:**

这段代码是 `gocode` 工具中一个关键的组成部分，它专注于理解 `gccgo` 编译器生成的包信息。通过解析 `.gox` 文件中的元数据，`gocode` 能够为使用 `gccgo` 编译的 Go 项目提供代码自动补全等功能。

Prompt: 
```
这是路径为go/src/github.com/nsf/gocode/_gccgo/package.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package main

import "debug/elf"
import "text/scanner"
import "bytes"
import "errors"
import "io"
import "fmt"
import "strconv"
import "go/ast"
import "go/token"
import "strings"

var builtin_type_names = []*ast.Ident{
	nil,
	ast.NewIdent("int8"),
	ast.NewIdent("int16"),
	ast.NewIdent("int32"),
	ast.NewIdent("int64"),
	ast.NewIdent("uint8"),
	ast.NewIdent("uint16"),
	ast.NewIdent("uint32"),
	ast.NewIdent("uint64"),
	ast.NewIdent("float32"),
	ast.NewIdent("float64"),
	ast.NewIdent("int"),
	ast.NewIdent("uint"),
	ast.NewIdent("uintptr"),
	nil,
	ast.NewIdent("bool"),
	ast.NewIdent("string"),
	ast.NewIdent("complex64"),
	ast.NewIdent("complex128"),
	ast.NewIdent("error"),
	ast.NewIdent("byte"),
	ast.NewIdent("rune"),
}

const (
	smallest_builtin_code = -21
)

func read_import_data(import_path string) ([]byte, error) {
	// TODO: find file location
	filename := import_path + ".gox"

	f, err := elf.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sec := f.Section(".go_export")
	if sec == nil {
		return nil, errors.New("missing .go_export section in the file: " + filename)
	}

	return sec.Data()
}

func parse_import_data(data []byte) {
	buf := bytes.NewBuffer(data)
	var p import_data_parser
	p.init(buf)

	// magic
	p.expect_ident("v1")
	p.expect(';')

	// package ident
	p.expect_ident("package")
	pkgid := p.expect(scanner.Ident)
	p.expect(';')

	println("package ident: " + pkgid)

	// package path
	p.expect_ident("pkgpath")
	pkgpath := p.expect(scanner.Ident)
	p.expect(';')

	println("package path: " + pkgpath)

	// package priority
	p.expect_ident("priority")
	priority := p.expect(scanner.Int)
	p.expect(';')

	println("package priority: " + priority)

	// import init functions
	for p.toktype == scanner.Ident && p.token() == "import" {
		p.expect_ident("import")
		pkgname := p.expect(scanner.Ident)
		pkgpath := p.expect(scanner.Ident)
		importpath := p.expect(scanner.String)
		p.expect(';')
		println("import " + pkgname + " " + pkgpath + " " + importpath)
	}

	if p.toktype == scanner.Ident && p.token() == "init" {
		p.expect_ident("init")
		for p.toktype != ';' {
			pkgname := p.expect(scanner.Ident)
			initname := p.expect(scanner.Ident)
			prio := p.expect(scanner.Int)
			println("init " + pkgname + " " + initname + " " + fmt.Sprint(prio))
		}
		p.expect(';')
	}

loop:
	for {
		switch tok := p.expect(scanner.Ident); tok {
		case "const":
			p.read_const()
		case "type":
			p.read_type_decl()
		case "var":
			p.read_var()
		case "func":
			p.read_func()
		case "checksum":
			p.read_checksum()
			break loop
		default:
			panic(errors.New("unexpected identifier token: '" + tok + "'"))
		}
	}
}

//----------------------------------------------------------------------------
// import data parser
//----------------------------------------------------------------------------

type import_data_type struct {
	name  string
	type_ ast.Expr
}

type import_data_parser struct {
	scanner   scanner.Scanner
	toktype   rune
	typetable []*import_data_type
}

func (this *import_data_parser) init(reader io.Reader) {
	this.scanner.Mode = scanner.ScanIdents | scanner.ScanInts | scanner.ScanStrings | scanner.ScanFloats
	this.scanner.Init(reader)
	this.next()

	// len == 1 here, because 0 is an invalid type index
	this.typetable = make([]*import_data_type, 1, 50)
}

func (this *import_data_parser) next() {
	this.toktype = this.scanner.Scan()
}

func (this *import_data_parser) token() string {
	return this.scanner.TokenText()
}

// internal, use expect(scanner.Ident) instead
func (this *import_data_parser) read_ident() string {
	id := ""
	prev := rune(0)

loop:
	for {
		switch this.toktype {
		case scanner.Ident:
			if prev == scanner.Ident {
				break loop
			}

			prev = this.toktype
			id += this.token()
			this.next()
		case '.', '?', '$':
			prev = this.toktype
			id += string(this.toktype)
			this.next()
		default:
			break loop
		}
	}

	if id == "" {
		this.errorf("identifier expected, got %s", scanner.TokenString(this.toktype))
	}
	return id
}

func (this *import_data_parser) read_int() string {
	val := ""
	if this.toktype == '-' {
		this.next()
		val += "-"
	}
	if this.toktype != scanner.Int {
		this.errorf("expected: %s, got: %s", scanner.TokenString(scanner.Int), scanner.TokenString(this.toktype))
	}

	val += this.token()
	this.next()
	return val
}

func (this *import_data_parser) errorf(format string, args ...interface{}) {
	panic(errors.New(fmt.Sprintf(format, args...)))
}

// makes sure that the current token is 'x', returns it and reads the next one
func (this *import_data_parser) expect(x rune) string {
	if x == scanner.Ident {
		// special case, in gccgo import data identifier is not exactly a scanner.Ident
		return this.read_ident()
	}

	if x == scanner.Int {
		// another special case, handle negative ints as well
		return this.read_int()
	}

	if this.toktype != x {
		this.errorf("expected: %s, got: %s", scanner.TokenString(x), scanner.TokenString(this.toktype))
	}

	tok := this.token()
	this.next()
	return tok
}

// makes sure that the following set of tokens matches 'special', reads the next one
func (this *import_data_parser) expect_special(special string) {
	i := 0
	for i < len(special) {
		if this.toktype != rune(special[i]) {
			break
		}

		this.next()
		i++
	}

	if i < len(special) {
		this.errorf("expected: \"%s\", got something else", special)
	}
}

// makes sure that the current token is scanner.Ident and is equals to 'ident', reads the next one
func (this *import_data_parser) expect_ident(ident string) {
	tok := this.expect(scanner.Ident)
	if tok != ident {
		this.errorf("expected identifier: \"%s\", got: \"%s\"", ident, tok)
	}
}

func (this *import_data_parser) read_type() ast.Expr {
	type_, name := this.read_type_full()
	if name != "" {
		return ast.NewIdent(name)
	}
	return type_
}

func (this *import_data_parser) read_type_full() (ast.Expr, string) {
	this.expect('<')
	this.expect_ident("type")

	numstr := this.expect(scanner.Int)
	num, err := strconv.ParseInt(numstr, 10, 32)
	if err != nil {
		panic(err)
	}

	if this.toktype == '>' {
		// was already declared previously
		this.next()
		if num < 0 {
			if num < smallest_builtin_code {
				this.errorf("out of range built-in type code")
			}
			return builtin_type_names[-num], ""
		} else {
			// lookup type table
			type_ := this.typetable[num]
			return type_.type_, type_.name
		}
	}

	this.typetable = append(this.typetable, &import_data_type{})
	var type_ = this.typetable[len(this.typetable)-1]

	switch this.toktype {
	case scanner.String:
		// named type
		s := this.expect(scanner.String)
		type_.name = s[1 : len(s)-1] // remove ""
		fallthrough
	default:
		// unnamed type
		switch this.toktype {
		case scanner.Ident:
			switch tok := this.token(); tok {
			case "struct":
				type_.type_ = this.read_struct_type()
			case "interface":
				type_.type_ = this.read_interface_type()
			case "map":
				type_.type_ = this.read_map_type()
			case "chan":
				type_.type_ = this.read_chan_type()
			default:
				this.errorf("unknown type class token: \"%s\"", tok)
			}
		case '[':
			type_.type_ = this.read_array_or_slice_type()
		case '*':
			this.next()
			if this.token() == "any" {
				this.next()
				type_.type_ = &ast.StarExpr{X: ast.NewIdent("any")}
			} else {
				type_.type_ = &ast.StarExpr{X: this.read_type()}
			}
		case '(':
			type_.type_ = this.read_func_type()
		case '<':
			type_.type_ = this.read_type()
		}
	}

	for this.toktype != '>' {
		// must be a method or many methods
		this.expect_ident("func")
		this.read_method()
	}

	this.expect('>')
	return type_.type_, type_.name
}

func (this *import_data_parser) read_map_type() ast.Expr {
	this.expect_ident("map")
	this.expect('[')
	key := this.read_type()
	this.expect(']')
	val := this.read_type()
	return &ast.MapType{Key: key, Value: val}
}

func (this *import_data_parser) read_chan_type() ast.Expr {
	dir := ast.SEND | ast.RECV
	this.expect_ident("chan")
	switch this.toktype {
	case '-':
		// chan -< <type>
		this.expect_special("-<")
		dir = ast.SEND
	case '<':
		// slight ambiguity here
		if this.scanner.Peek() == '-' {
			// chan <- <type>
			this.expect_special("<-")
			dir = ast.RECV
		}
		// chan <type>
	default:
		this.errorf("unexpected token: \"%s\"", this.token())
	}

	return &ast.ChanType{Dir: dir, Value: this.read_type()}
}

func (this *import_data_parser) read_field() *ast.Field {
	var tag string
	name := this.expect(scanner.Ident)
	type_ := this.read_type()
	if this.toktype == scanner.String {
		tag = this.expect(scanner.String)
	}

	return &ast.Field{
		Names: []*ast.Ident{ast.NewIdent(name)},
		Type:  type_,
		Tag:   &ast.BasicLit{Kind: token.STRING, Value: tag},
	}
}

func (this *import_data_parser) read_struct_type() ast.Expr {
	var fields []*ast.Field
	read_field := func() {
		field := this.read_field()
		fields = append(fields, field)
	}

	this.expect_ident("struct")
	this.expect('{')
	for this.toktype != '}' {
		read_field()
		this.expect(';')
	}
	this.expect('}')
	return &ast.StructType{Fields: &ast.FieldList{List: fields}}
}

func (this *import_data_parser) read_parameter() *ast.Field {
	name := this.expect(scanner.Ident)

	var type_ ast.Expr
	if this.toktype == '.' {
		this.expect_special("...")
		type_ = &ast.Ellipsis{Elt: this.read_type()}
	} else {
		type_ = this.read_type()
	}

	var tag string
	if this.toktype == scanner.String {
		tag = this.expect(scanner.String)
	}

	return &ast.Field{
		Names: []*ast.Ident{ast.NewIdent(name)},
		Type:  type_,
		Tag:   &ast.BasicLit{Kind: token.STRING, Value: tag},
	}
}

func (this *import_data_parser) read_parameters() *ast.FieldList {
	var fields []*ast.Field
	read_parameter := func() {
		parameter := this.read_parameter()
		fields = append(fields, parameter)
	}

	this.expect('(')
	if this.toktype != ')' {
		read_parameter()
		for this.toktype == ',' {
			this.next() // skip ','
			read_parameter()
		}
	}
	this.expect(')')

	if fields == nil {
		return nil
	}
	return &ast.FieldList{List: fields}
}

func (this *import_data_parser) read_func_type() *ast.FuncType {
	var params, results *ast.FieldList

	params = this.read_parameters()
	switch this.toktype {
	case '<':
		field := &ast.Field{Type: this.read_type()}
		results = &ast.FieldList{List: []*ast.Field{field}}
	case '(':
		results = this.read_parameters()
	}

	return &ast.FuncType{Params: params, Results: results}
}

func (this *import_data_parser) read_method_or_embed_spec() *ast.Field {
	var type_ ast.Expr
	name := this.expect(scanner.Ident)
	if name == "?" {
		// TODO: ast.SelectorExpr conversion here possibly
		type_ = this.read_type()
	} else {
		type_ = this.read_func_type()
	}
	return &ast.Field{
		Names: []*ast.Ident{ast.NewIdent(name)},
		Type:  type_,
	}
}

func (this *import_data_parser) read_interface_type() ast.Expr {
	var methods []*ast.Field
	read_method := func() {
		method := this.read_method_or_embed_spec()
		methods = append(methods, method)
	}

	this.expect_ident("interface")
	this.expect('{')
	for this.toktype != '}' {
		read_method()
		this.expect(';')
	}
	this.expect('}')
	return &ast.InterfaceType{Methods: &ast.FieldList{List: methods}}
}

func (this *import_data_parser) read_method() {
	var buf1, buf2 bytes.Buffer
	recv := this.read_parameters()
	name := this.expect(scanner.Ident)
	type_ := this.read_func_type()
	this.expect(';')
	pretty_print_type_expr(&buf1, recv.List[0].Type)
	pretty_print_type_expr(&buf2, type_)
	println("func (" + buf1.String() + ") " + name + buf2.String()[4:])
}

func (this *import_data_parser) read_array_or_slice_type() ast.Expr {
	var length ast.Expr

	this.expect('[')
	if this.toktype == scanner.Int {
		// array type
		length = &ast.BasicLit{Kind: token.INT, Value: this.expect(scanner.Int)}
	}
	this.expect(']')
	return &ast.ArrayType{
		Len: length,
		Elt: this.read_type(),
	}
}

func (this *import_data_parser) read_const() {
	var buf bytes.Buffer

	// const keyword was already consumed
	c := "const " + this.expect(scanner.Ident)
	if this.toktype != '=' {
		// parse type
		type_ := this.read_type()
		pretty_print_type_expr(&buf, type_)
		c += " " + buf.String()
	}

	this.expect('=')

	// parse expr
	this.next()
	this.expect(';')
	println(c)
}

func (this *import_data_parser) read_checksum() {
	// checksum keyword was already consumed
	for this.toktype != ';' {
		this.next()
	}
	this.expect(';')
}

func (this *import_data_parser) read_type_decl() {
	var buf bytes.Buffer
	// type keyword was already consumed
	type_, name := this.read_type_full()
	this.expect(';')
	pretty_print_type_expr(&buf, type_)
	println("type " + name + " " + buf.String())
}

func (this *import_data_parser) read_var() {
	var buf bytes.Buffer
	// var keyword was already consumed
	name := this.expect(scanner.Ident)
	type_ := this.read_type()
	this.expect(';')
	pretty_print_type_expr(&buf, type_)
	println("var " + name + " " + buf.String())
}

func (this *import_data_parser) read_func() {
	var buf bytes.Buffer
	// func keyword was already consumed
	name := this.expect(scanner.Ident)
	type_ := this.read_func_type()
	this.expect(';')
	pretty_print_type_expr(&buf, type_)
	println("func " + name + buf.String()[4:])
}

//-------------------------------------------------------------------------
// Pretty printing
//-------------------------------------------------------------------------

func get_array_len(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.BasicLit:
		return string(t.Value)
	case *ast.Ellipsis:
		return "..."
	}
	return ""
}

func pretty_print_type_expr(out io.Writer, e ast.Expr) {
	switch t := e.(type) {
	case *ast.StarExpr:
		fmt.Fprintf(out, "*")
		pretty_print_type_expr(out, t.X)
	case *ast.Ident:
		if strings.HasPrefix(t.Name, "$") {
			// beautify anonymous types
			switch t.Name[1] {
			case 's':
				fmt.Fprintf(out, "struct")
			case 'i':
				fmt.Fprintf(out, "interface")
			}
		} else {
			fmt.Fprintf(out, t.Name)
		}
	case *ast.ArrayType:
		al := ""
		if t.Len != nil {
			println(t.Len)
			al = get_array_len(t.Len)
		}
		if al != "" {
			fmt.Fprintf(out, "[%s]", al)
		} else {
			fmt.Fprintf(out, "[]")
		}
		pretty_print_type_expr(out, t.Elt)
	case *ast.SelectorExpr:
		pretty_print_type_expr(out, t.X)
		fmt.Fprintf(out, ".%s", t.Sel.Name)
	case *ast.FuncType:
		fmt.Fprintf(out, "func(")
		pretty_print_func_field_list(out, t.Params)
		fmt.Fprintf(out, ")")

		buf := bytes.NewBuffer(make([]byte, 0, 256))
		nresults := pretty_print_func_field_list(buf, t.Results)
		if nresults > 0 {
			results := buf.String()
			if strings.Index(results, ",") != -1 {
				results = "(" + results + ")"
			}
			fmt.Fprintf(out, " %s", results)
		}
	case *ast.MapType:
		fmt.Fprintf(out, "map[")
		pretty_print_type_expr(out, t.Key)
		fmt.Fprintf(out, "]")
		pretty_print_type_expr(out, t.Value)
	case *ast.InterfaceType:
		fmt.Fprintf(out, "interface{}")
	case *ast.Ellipsis:
		fmt.Fprintf(out, "...")
		pretty_print_type_expr(out, t.Elt)
	case *ast.StructType:
		fmt.Fprintf(out, "struct")
	case *ast.ChanType:
		switch t.Dir {
		case ast.RECV:
			fmt.Fprintf(out, "<-chan ")
		case ast.SEND:
			fmt.Fprintf(out, "chan<- ")
		case ast.SEND | ast.RECV:
			fmt.Fprintf(out, "chan ")
		}
		pretty_print_type_expr(out, t.Value)
	case *ast.ParenExpr:
		fmt.Fprintf(out, "(")
		pretty_print_type_expr(out, t.X)
		fmt.Fprintf(out, ")")
	case *ast.BadExpr:
		// TODO: probably I should check that in a separate function
		// and simply discard declarations with BadExpr as a part of their
		// type
	default:
		// should never happen
		panic("unknown type")
	}
}

func pretty_print_func_field_list(out io.Writer, f *ast.FieldList) int {
	count := 0
	if f == nil {
		return count
	}
	for i, field := range f.List {
		// names
		if field.Names != nil {
			hasNonblank := false
			for j, name := range field.Names {
				if name.Name != "?" {
					hasNonblank = true
					fmt.Fprintf(out, "%s", name.Name)
					if j != len(field.Names)-1 {
						fmt.Fprintf(out, ", ")
					}
				}
				count++
			}
			if hasNonblank {
				fmt.Fprintf(out, " ")
			}
		} else {
			count++
		}

		// type
		pretty_print_type_expr(out, field.Type)

		// ,
		if i != len(f.List)-1 {
			fmt.Fprintf(out, ", ")
		}
	}
	return count
}

func main() {
	data, err := read_import_data("io")
	if err != nil {
		panic(err)
	}
	parse_import_data(data)
}

"""



```