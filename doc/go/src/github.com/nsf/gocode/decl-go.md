Response:
The user wants to understand the functionality of the provided Go code snippet from `go/src/github.com/nsf/gocode/decl.go`. I need to analyze the code and explain its purpose, particularly focusing on the `decl` struct and related functions.

Here's a breakdown of the thought process:

1. **Identify the core data structure:** The code prominently features the `decl` struct. This is likely the central element for representing declarations in Go code.

2. **Analyze the `decl` struct fields:**  Each field in the `decl` struct likely holds important information about a declaration. I'll go through each field and try to understand its meaning:
    * `name`: The name of the declared entity.
    * `typ`:  An `ast.Expr`, likely representing the type of the declaration.
    * `class`: A `decl_class`, indicating the kind of declaration (constant, function, etc.).
    * `flags`: `decl_flags`, storing metadata about the declaration (e.g., imported, range variable).
    * `children`: A map of `string` to `*decl`, suggesting nested declarations or members.
    * `embedded`: A slice of `ast.Expr`, probably for embedded types in structs or interfaces.
    * `value`: An `ast.Expr`, potentially holding the value of the declaration (especially for constants or variables).
    * `value_index`: An integer, possibly used for indexing within multi-valued expressions (like function returns).
    * `scope`: A pointer to a `scope`, indicating the lexical scope of the declaration.

3. **Examine related types and constants:** The `decl_class` and `decl_flags` enums provide more context about the kinds of declarations and their properties.

4. **Analyze functions related to `decl`:**  Functions like `new_decl`, `new_decl_full`, `ast_decl_type`, `ast_decl_class`, etc., seem to be utility functions for creating and extracting information about `decl` objects from the Go AST.

5. **Look for patterns and relationships:**  Notice the functions dealing with anonymous types (`anonymous_id_gen`, `check_for_anon_type`, `anonymify_ast`). This suggests a mechanism for handling types without explicit names. The functions related to type inference (`infer_type`, `advance_to_type`) indicate a crucial aspect of the code.

6. **Formulate a high-level summary:**  Based on the above analysis, the primary function of this code is to represent and manage Go language declarations. It appears to be part of a system that analyzes Go code, likely for features like autocompletion or code navigation.

7. **Address specific requirements from the prompt:**
    * **List the functions:** Enumerate the key functions and their roles.
    * **Infer Go language feature:**  The code strongly suggests the implementation of a system for understanding Go code structure, particularly declarations and their types. This is essential for features like code completion, go-to-definition, etc.
    * **Go code example:** Create a simple Go example and illustrate how the `decl` structure would represent its elements.
    * **Assumptions for code inference:**  Clearly state the assumptions made during the analysis, such as the input being a Go AST.
    * **Command-line parameters:** This part of the code doesn't seem to involve command-line arguments, so explicitly state that.
    * **User error points:**  Consider potential pitfalls, such as incorrect type inference or issues with anonymous types. However, based *only* on this snippet, there isn't enough context to definitively say what a user might do wrong. It's more about the *code's* correctness in representing declarations.
    * **Functionality summary for part 1:** Summarize the core responsibility of the code based on the analysis so far.

8. **Structure the answer:** Organize the findings logically, starting with the core functionality, then explaining the key components, and finally addressing the specific points from the prompt. Use clear and concise language.
这段代码是 Go 语言工具 `gocode` 的一部分，路径为 `go/src/github.com/nsf/gocode/decl.go`，它主要负责 **表示和处理 Go 语言代码中的声明 (declarations)**。

**核心功能归纳：**

1. **定义了表示 Go 语言声明的数据结构 `decl`：**  `decl` 结构体是这段代码的核心，它包含了关于一个声明的各种信息，例如声明的名称、类型、类别（常量、变量、函数等）、标志（是否是导入的、是否是类型别名等）、子元素（例如结构体或接口的字段和方法）、嵌入类型以及相关的类型推断信息。

2. **定义了声明的类别 `decl_class` 和标志 `decl_flags`：**  这些枚举类型用于更细致地描述声明的性质。例如，`decl_class` 可以是 `decl_const`、`decl_func`、`decl_type` 等，而 `decl_flags` 可以表示 `decl_foreign`（来自其他包）或 `decl_alias`（类型别名）。

3. **提供了一系列用于创建和操作 `decl` 结构体的函数：** 例如 `new_decl`、`new_decl_full` 用于创建 `decl` 对象，`ast_decl_type`、`ast_decl_class` 用于从 Go 语言的抽象语法树 (AST) 节点中提取声明的类型和类别信息， `ast_field_list_to_decls` 用于将字段列表转换为 `decl` 映射，等等。

4. **实现了匿名类型处理机制：** 通过 `anonymous_id_gen` 结构体和相关的函数 (`check_for_anon_type`, `anonymify_ast`)，代码能够识别和处理匿名结构体和接口类型，并为它们生成临时的名称。

5. **提供了类型推断的基础设施：**  `infer_type` 函数及其相关的辅助函数（如 `advance_to_type`）是实现类型推断的关键部分。它可以根据表达式推断出其类型。

6. **支持查找声明的子元素和嵌入类型：**  `find_child` 和 `find_child_and_in_embedded` 函数用于在 `decl` 结构体中查找特定的子声明，包括通过嵌入类型查找。

7. **实现了类型别名的处理：**  通过 `decl_alias` 标志和 `type_dealias` 函数，代码能够处理类型别名，并找到别名指向的实际类型。

8. **提供了用于范围 (range) 语句的特殊类型推断逻辑：** `infer_range_type` 函数专门用于推断 `range` 语句中迭代变量的类型。

**它可以推理出这是 `gocode` 工具用于理解 Go 语言代码结构的核心部分，特别是关于声明的表示和类型信息的获取。这对于代码自动补全、跳转到定义等功能至关重要。**

**Go 代码示例：**

假设我们有以下 Go 代码：

```go
package main

type MyInt int

type MyStruct struct {
	Field1 int
	Field2 string
}

const MyConst = 10

var MyVar int = 5

func MyFunc(a int) string {
	return ""
}

func main() {
	var s MyStruct
	println(s.Field1)
}
```

当 `gocode` 解析这段代码时，`decl.go` 中的结构体和函数会用于创建表示这些声明的 `decl` 对象。

**假设输入：**  Go 语言的抽象语法树 (AST)，代表了上面的 `main.go` 文件。

**部分输出（简化的 `decl` 结构体表示）：**

* **`decl` for `package main`:**
    * `name`: "main"
    * `class`: `decl_package`

* **`decl` for `type MyInt int`:**
    * `name`: "MyInt"
    * `class`: `decl_type`
    * `typ`: `ast.Ident{Name: "int"}`
    * `flags`: `decl_alias`

* **`decl` for `type MyStruct struct { ... }`:**
    * `name`: "MyStruct"
    * `class`: `decl_type`
    * `typ`: `ast.StructType{...}`
    * `children`:
        * "Field1": `decl{name: "Field1", class: decl_var, typ: ast.Ident{Name: "int"}}`
        * "Field2": `decl{name: "Field2", class: decl_var, typ: ast.Ident{Name: "string"}}`

* **`decl` for `const MyConst = 10`:**
    * `name`: "MyConst"
    * `class`: `decl_const`
    * `typ`: `ast.Ident{Name: "int"}`
    * `value`: `ast.BasicLit{Value: "10", Kind: token.INT}`

* **`decl` for `var MyVar int = 5`:**
    * `name`: "MyVar"
    * `class`: `decl_var`
    * `typ`: `ast.Ident{Name: "int"}`
    * `value`: `ast.BasicLit{Value: "5", Kind: token.INT}`

* **`decl` for `func MyFunc(a int) string { ... }`:**
    * `name`: "MyFunc"
    * `class`: `decl_func`
    * `typ`: `ast.FuncType{...}`

**代码推理示例：**

假设在 `gocode` 的某个地方需要知道 `s.Field1` 的类型。  `infer_type` 函数可能会被调用，输入是表示 `s.Field1` 的 `ast.SelectorExpr` 和当前的作用域信息。

1. `infer_type` 会首先推断 `s` 的类型，它会找到 `MyStruct` 的 `decl`。
2. 接着，它会尝试在 `MyStruct` 的 `decl` 的 `children` 中查找名为 "Field1" 的子声明。
3. 找到 "Field1" 的 `decl` 后，其 `typ` 字段 `ast.Ident{Name: "int"}` 就代表了 `s.Field1` 的类型。

**命令行参数处理：**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `gocode` 的入口文件 (`main.go` 或类似的文件）中。这里定义的结构体和函数是 `gocode` 内部逻辑的一部分，用于表示和操作代码信息。

**使用者易犯错的点（更多是针对 `gocode` 开发者或维护者）：**

1. **类型推断的复杂性：**  Go 语言的类型系统相对复杂，编写正确的类型推断逻辑需要考虑各种情况，例如接口、方法集、类型转换、泛型（虽然这段代码看起来是在泛型引入之前编写的）。  一个常见的错误是未能处理某些边缘情况，导致类型推断不准确。

2. **匿名类型的处理：**  正确地生成和管理匿名类型的临时名称，并确保在后续处理中能够正确识别这些类型，也是一个容易出错的点。

3. **作用域管理：**  `decl` 结构体中包含了 `scope` 信息，正确地维护和使用作用域信息对于类型查找和名称解析至关重要。错误的作用域管理可能导致找到错误的声明。

4. **并发安全：** `anonymous_id_gen` 使用了 `sync.Mutex`，说明在生成匿名类型 ID 时需要考虑并发安全。如果其他部分的代码在操作 `decl` 结构体时没有进行适当的同步，可能会出现数据竞争等问题。

**功能归纳 (针对第 1 部分)：**

这段代码（`decl.go` 的第 1 部分）的核心功能是 **定义了表示 Go 语言声明的关键数据结构 (`decl`) 及其相关的辅助类型和函数，为 `gocode` 工具提供了理解和分析 Go 代码的基础框架，特别是用于表示代码中的各种声明信息和进行初步的类型推断。** 它奠定了 `gocode` 理解代码结构和进行代码补全等功能的基础。

Prompt: 
```
这是路径为go/src/github.com/nsf/gocode/decl.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第1部分，共2部分，请归纳一下它的功能

"""
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/token"
	"io"
	"reflect"
	"strings"
	"sync"
)

// decl.class
type decl_class int16

const (
	decl_invalid = decl_class(-1 + iota)

	// these are in a sorted order
	decl_const
	decl_func
	decl_import
	decl_package
	decl_type
	decl_var

	// this one serves as a temporary type for those methods that were
	// declared before their actual owner
	decl_methods_stub
)

func (this decl_class) String() string {
	switch this {
	case decl_invalid:
		return "PANIC"
	case decl_const:
		return "const"
	case decl_func:
		return "func"
	case decl_import:
		return "import"
	case decl_package:
		return "package"
	case decl_type:
		return "type"
	case decl_var:
		return "var"
	case decl_methods_stub:
		return "IF YOU SEE THIS, REPORT A BUG" // :D
	}
	panic("unreachable")
}

// decl.flags
type decl_flags int16

const (
	decl_foreign decl_flags = 1 << iota // imported from another package

	// means that the decl is a part of the range statement
	// its type is inferred in a special way
	decl_rangevar

	// decl of decl_type class is a type alias
	decl_alias

	// for preventing infinite recursions and loops in type inference code
	decl_visited
)

//-------------------------------------------------------------------------
// decl
//
// The most important data structure of the whole gocode project. It
// describes a single declaration and its children.
//-------------------------------------------------------------------------

type decl struct {
	// Name starts with '$' if the declaration describes an anonymous type.
	// '$s_%d' for anonymous struct types
	// '$i_%d' for anonymous interface types
	name  string
	typ   ast.Expr
	class decl_class
	flags decl_flags

	// functions for interface type, fields+methods for struct type
	children map[string]*decl

	// embedded types
	embedded []ast.Expr

	// if the type is unknown at AST building time, I'm using these
	value ast.Expr

	// if it's a multiassignment and the Value is a CallExpr, it is being set
	// to an index into the return value tuple, otherwise it's a -1
	value_index int

	// scope where this Decl was declared in (not its visibilty scope!)
	// Decl uses it for type inference
	scope *scope
}

func ast_decl_type(d ast.Decl) ast.Expr {
	switch t := d.(type) {
	case *ast.GenDecl:
		switch t.Tok {
		case token.CONST, token.VAR:
			c := t.Specs[0].(*ast.ValueSpec)
			return c.Type
		case token.TYPE:
			t := t.Specs[0].(*ast.TypeSpec)
			return t.Type
		}
	case *ast.FuncDecl:
		return t.Type
	}
	panic("unreachable")
}

func ast_decl_flags(d ast.Decl) decl_flags {
	switch t := d.(type) {
	case *ast.GenDecl:
		switch t.Tok {
		case token.TYPE:
			if isAliasTypeSpec(t.Specs[0].(*ast.TypeSpec)) {
				return decl_alias
			}
		}
	}
	return 0
}

func ast_decl_class(d ast.Decl) decl_class {
	switch t := d.(type) {
	case *ast.GenDecl:
		switch t.Tok {
		case token.VAR:
			return decl_var
		case token.CONST:
			return decl_const
		case token.TYPE:
			return decl_type
		}
	case *ast.FuncDecl:
		return decl_func
	}
	panic("unreachable")
}

func ast_decl_convertable(d ast.Decl) bool {
	switch t := d.(type) {
	case *ast.GenDecl:
		switch t.Tok {
		case token.VAR, token.CONST, token.TYPE:
			return true
		}
	case *ast.FuncDecl:
		return true
	}
	return false
}

func ast_field_list_to_decls(f *ast.FieldList, class decl_class, flags decl_flags, scope *scope, add_anonymous bool) map[string]*decl {
	count := 0
	for _, field := range f.List {
		count += len(field.Names)
	}

	decls := make(map[string]*decl, count)
	for _, field := range f.List {
		for _, name := range field.Names {
			if flags&decl_foreign != 0 && !ast.IsExported(name.Name) {
				continue
			}
			d := &decl{
				name:        name.Name,
				typ:         field.Type,
				class:       class,
				flags:       flags,
				scope:       scope,
				value_index: -1,
			}
			decls[d.name] = d
		}

		// add anonymous field as a child (type embedding)
		if class == decl_var && field.Names == nil && add_anonymous {
			tp := get_type_path(field.Type)
			if flags&decl_foreign != 0 && !ast.IsExported(tp.name) {
				continue
			}
			d := &decl{
				name:        tp.name,
				typ:         field.Type,
				class:       class,
				flags:       flags,
				scope:       scope,
				value_index: -1,
			}
			decls[d.name] = d
		}
	}
	return decls
}

func ast_field_list_to_embedded(f *ast.FieldList) []ast.Expr {
	count := 0
	for _, field := range f.List {
		if field.Names == nil || field.Names[0].Name == "?" {
			count++
		}
	}

	if count == 0 {
		return nil
	}

	embedded := make([]ast.Expr, count)
	i := 0
	for _, field := range f.List {
		if field.Names == nil || field.Names[0].Name == "?" {
			embedded[i] = field.Type
			i++
		}
	}

	return embedded
}

func ast_type_to_embedded(ty ast.Expr) []ast.Expr {
	switch t := ty.(type) {
	case *ast.StructType:
		return ast_field_list_to_embedded(t.Fields)
	case *ast.InterfaceType:
		return ast_field_list_to_embedded(t.Methods)
	}
	return nil
}

func ast_type_to_children(ty ast.Expr, flags decl_flags, scope *scope) map[string]*decl {
	switch t := ty.(type) {
	case *ast.StructType:
		return ast_field_list_to_decls(t.Fields, decl_var, flags, scope, true)
	case *ast.InterfaceType:
		return ast_field_list_to_decls(t.Methods, decl_func, flags, scope, false)
	}
	return nil
}

//-------------------------------------------------------------------------
// anonymous_id_gen
//
// ID generator for anonymous types (thread-safe)
//-------------------------------------------------------------------------

type anonymous_id_gen struct {
	sync.Mutex
	i int
}

func (a *anonymous_id_gen) gen() (id int) {
	a.Lock()
	defer a.Unlock()
	id = a.i
	a.i++
	return
}

var g_anon_gen anonymous_id_gen

//-------------------------------------------------------------------------

func check_for_anon_type(t ast.Expr, flags decl_flags, s *scope) ast.Expr {
	if t == nil {
		return nil
	}
	var name string

	switch t.(type) {
	case *ast.StructType:
		name = fmt.Sprintf("$s_%d", g_anon_gen.gen())
	case *ast.InterfaceType:
		name = fmt.Sprintf("$i_%d", g_anon_gen.gen())
	}

	if name != "" {
		anonymify_ast(t, flags, s)
		d := new_decl_full(name, decl_type, flags, t, nil, -1, s)
		s.add_named_decl(d)
		return ast.NewIdent(name)
	}
	return t
}

//-------------------------------------------------------------------------

func new_decl_full(name string, class decl_class, flags decl_flags, typ, v ast.Expr, vi int, s *scope) *decl {
	if name == "_" {
		return nil
	}
	d := new(decl)
	d.name = name
	d.class = class
	d.flags = flags
	d.typ = typ
	d.value = v
	d.value_index = vi
	d.scope = s
	d.children = ast_type_to_children(d.typ, flags, s)
	d.embedded = ast_type_to_embedded(d.typ)
	return d
}

func new_decl(name string, class decl_class, scope *scope) *decl {
	decl := new(decl)
	decl.name = name
	decl.class = class
	decl.value_index = -1
	decl.scope = scope
	return decl
}

func new_decl_var(name string, typ ast.Expr, value ast.Expr, vindex int, scope *scope) *decl {
	if name == "_" {
		return nil
	}
	decl := new(decl)
	decl.name = name
	decl.class = decl_var
	decl.typ = typ
	decl.value = value
	decl.value_index = vindex
	decl.scope = scope
	return decl
}

func method_of(d ast.Decl) string {
	if t, ok := d.(*ast.FuncDecl); ok {
		if t.Recv != nil && len(t.Recv.List) != 0 {
			switch t := t.Recv.List[0].Type.(type) {
			case *ast.StarExpr:
				if se, ok := t.X.(*ast.SelectorExpr); ok {
					return se.Sel.Name
				}
				if ident, ok := t.X.(*ast.Ident); ok {
					return ident.Name
				}
				return ""
			case *ast.Ident:
				return t.Name
			default:
				return ""
			}
		}
	}
	return ""
}

func (other *decl) deep_copy() *decl {
	d := new(decl)
	d.name = other.name
	d.class = other.class
	d.flags = other.flags
	d.typ = other.typ
	d.value = other.value
	d.value_index = other.value_index
	d.children = make(map[string]*decl, len(other.children))
	for key, value := range other.children {
		d.children[key] = value
	}
	if other.embedded != nil {
		d.embedded = make([]ast.Expr, len(other.embedded))
		copy(d.embedded, other.embedded)
	}
	d.scope = other.scope
	return d
}

func (d *decl) is_rangevar() bool {
	return d.flags&decl_rangevar != 0
}

func (d *decl) is_alias() bool {
	return d.flags&decl_alias != 0
}

func (d *decl) is_visited() bool {
	return d.flags&decl_visited != 0
}

func (d *decl) set_visited() {
	d.flags |= decl_visited
}

func (d *decl) clear_visited() {
	d.flags &^= decl_visited
}

func (d *decl) expand_or_replace(other *decl) {
	// expand only if it's a methods stub, otherwise simply keep it as is
	if d.class != decl_methods_stub && other.class != decl_methods_stub {
		return
	}

	if d.class == decl_methods_stub {
		d.typ = other.typ
		d.class = other.class
		d.flags = other.flags
	}

	if other.children != nil {
		for _, c := range other.children {
			d.add_child(c)
		}
	}

	if other.embedded != nil {
		d.embedded = other.embedded
		d.scope = other.scope
	}
}

func (d *decl) matches() bool {
	if strings.HasPrefix(d.name, "$") || d.class == decl_methods_stub {
		return false
	}
	return true
}

func (d *decl) pretty_print_type(out io.Writer, canonical_aliases map[string]string) {
	switch d.class {
	case decl_type:
		switch d.typ.(type) {
		case *ast.StructType:
			// TODO: not used due to anonymify?
			fmt.Fprintf(out, "struct")
		case *ast.InterfaceType:
			// TODO: not used due to anonymify?
			fmt.Fprintf(out, "interface")
		default:
			if d.typ != nil {
				pretty_print_type_expr(out, d.typ, canonical_aliases)
			}
		}
	case decl_var:
		if d.typ != nil {
			pretty_print_type_expr(out, d.typ, canonical_aliases)
		}
	case decl_func:
		pretty_print_type_expr(out, d.typ, canonical_aliases)
	}
}

func (d *decl) add_child(cd *decl) {
	if d.children == nil {
		d.children = make(map[string]*decl)
	}
	d.children[cd.name] = cd
}

func check_for_builtin_funcs(typ *ast.Ident, c *ast.CallExpr, scope *scope) (ast.Expr, *scope) {
	if strings.HasPrefix(typ.Name, "func(") {
		if t, ok := c.Fun.(*ast.Ident); ok {
			switch t.Name {
			case "new":
				if len(c.Args) > 0 {
					e := new(ast.StarExpr)
					e.X = c.Args[0]
					return e, scope
				}
			case "make":
				if len(c.Args) > 0 {
					return c.Args[0], scope
				}
			case "append":
				if len(c.Args) > 0 {
					t, scope, _ := infer_type(c.Args[0], scope, -1)
					return t, scope
				}
			case "complex":
				// TODO: fix it
				return ast.NewIdent("complex"), g_universe_scope
			case "closed":
				return ast.NewIdent("bool"), g_universe_scope
			case "cap":
				return ast.NewIdent("int"), g_universe_scope
			case "copy":
				return ast.NewIdent("int"), g_universe_scope
			case "len":
				return ast.NewIdent("int"), g_universe_scope
			}
			// TODO:
			// func recover() interface{}
			// func imag(c ComplexType) FloatType
			// func real(c ComplexType) FloatType
		}
	}
	return nil, nil
}

func func_return_type(f *ast.FuncType, index int) ast.Expr {
	if f.Results == nil {
		return nil
	}

	if index == -1 {
		return f.Results.List[0].Type
	}

	i := 0
	var field *ast.Field
	for _, field = range f.Results.List {
		n := 1
		if field.Names != nil {
			n = len(field.Names)
		}
		if i <= index && index < i+n {
			return field.Type
		}
		i += n
	}
	return nil
}

type type_path struct {
	pkg  string
	name string
}

func (tp *type_path) is_nil() bool {
	return tp.pkg == "" && tp.name == ""
}

// converts type expressions like:
// ast.Expr
// *ast.Expr
// $ast$go/ast.Expr
// to a path that can be used to lookup a type related Decl
func get_type_path(e ast.Expr) (r type_path) {
	if e == nil {
		return type_path{"", ""}
	}

	switch t := e.(type) {
	case *ast.Ident:
		r.name = t.Name
	case *ast.StarExpr:
		r = get_type_path(t.X)
	case *ast.SelectorExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			r.pkg = ident.Name
		}
		r.name = t.Sel.Name
	}
	return
}

func lookup_path(tp type_path, scope *scope) *decl {
	if tp.is_nil() {
		return nil
	}
	var decl *decl
	if tp.pkg != "" {
		decl = scope.lookup(tp.pkg)
		// return nil early if the package wasn't found but it's part
		// of the type specification
		if decl == nil {
			return nil
		}
	}

	if decl != nil {
		if tp.name != "" {
			return decl.find_child(tp.name)
		} else {
			return decl
		}
	}

	return scope.lookup(tp.name)
}

func lookup_pkg(tp type_path, scope *scope) string {
	if tp.is_nil() {
		return ""
	}
	if tp.pkg == "" {
		return ""
	}
	decl := scope.lookup(tp.pkg)
	if decl == nil {
		return ""
	}
	return decl.name
}

func type_to_decl(t ast.Expr, scope *scope) *decl {
	tp := get_type_path(t)
	d := lookup_path(tp, scope)
	if d != nil && d.class == decl_var {
		// weird variable declaration pointing to itself
		return nil
	}
	return d
}

func expr_to_decl(e ast.Expr, scope *scope) *decl {
	t, scope, _ := infer_type(e, scope, -1)
	return type_to_decl(t, scope)
}

//-------------------------------------------------------------------------
// Type inference
//-------------------------------------------------------------------------

type type_predicate func(ast.Expr) bool

func advance_to_type(pred type_predicate, v ast.Expr, scope *scope) (ast.Expr, *scope) {
	if pred(v) {
		return v, scope
	}

	decl := type_to_decl(v, scope)
	if decl == nil {
		return nil, nil
	}

	if decl.is_visited() {
		return nil, nil
	}
	decl.set_visited()
	defer decl.clear_visited()

	return advance_to_type(pred, decl.typ, decl.scope)
}

func advance_to_struct_or_interface(decl *decl) *decl {
	if decl.is_visited() {
		return nil
	}
	decl.set_visited()
	defer decl.clear_visited()

	if struct_interface_predicate(decl.typ) {
		return decl
	}

	decl = type_to_decl(decl.typ, decl.scope)
	if decl == nil {
		return nil
	}
	return advance_to_struct_or_interface(decl)
}

func struct_interface_predicate(v ast.Expr) bool {
	switch v.(type) {
	case *ast.StructType, *ast.InterfaceType:
		return true
	}
	return false
}

func chan_predicate(v ast.Expr) bool {
	_, ok := v.(*ast.ChanType)
	return ok
}

func index_predicate(v ast.Expr) bool {
	switch v.(type) {
	case *ast.ArrayType, *ast.MapType, *ast.Ellipsis:
		return true
	}
	return false
}

func star_predicate(v ast.Expr) bool {
	_, ok := v.(*ast.StarExpr)
	return ok
}

func func_predicate(v ast.Expr) bool {
	_, ok := v.(*ast.FuncType)
	return ok
}

func range_predicate(v ast.Expr) bool {
	switch t := v.(type) {
	case *ast.Ident:
		if t.Name == "string" {
			return true
		}
	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.Ellipsis:
		return true
	}
	return false
}

type anonymous_typer struct {
	flags decl_flags
	scope *scope
}

func (a *anonymous_typer) Visit(node ast.Node) ast.Visitor {
	switch t := node.(type) {
	case *ast.CompositeLit:
		t.Type = check_for_anon_type(t.Type, a.flags, a.scope)
	case *ast.MapType:
		t.Key = check_for_anon_type(t.Key, a.flags, a.scope)
		t.Value = check_for_anon_type(t.Value, a.flags, a.scope)
	case *ast.ArrayType:
		t.Elt = check_for_anon_type(t.Elt, a.flags, a.scope)
	case *ast.Ellipsis:
		t.Elt = check_for_anon_type(t.Elt, a.flags, a.scope)
	case *ast.ChanType:
		t.Value = check_for_anon_type(t.Value, a.flags, a.scope)
	case *ast.Field:
		t.Type = check_for_anon_type(t.Type, a.flags, a.scope)
	case *ast.CallExpr:
		t.Fun = check_for_anon_type(t.Fun, a.flags, a.scope)
	case *ast.ParenExpr:
		t.X = check_for_anon_type(t.X, a.flags, a.scope)
	case *ast.StarExpr:
		t.X = check_for_anon_type(t.X, a.flags, a.scope)
	case *ast.GenDecl:
		switch t.Tok {
		case token.VAR:
			for _, s := range t.Specs {
				vs := s.(*ast.ValueSpec)
				vs.Type = check_for_anon_type(vs.Type, a.flags, a.scope)
			}
		case token.TYPE:
			for _, s := range t.Specs {
				ts := s.(*ast.TypeSpec)
				if isAliasTypeSpec(ts) {
					ts.Type = check_for_anon_type(ts.Type, a.flags, a.scope)
				}
			}
		}
	}
	return a
}

func anonymify_ast(node ast.Node, flags decl_flags, scope *scope) {
	v := anonymous_typer{flags, scope}
	ast.Walk(&v, node)
}

// RETURNS:
// 	- type expression which represents a full name of a type
//	- bool whether a type expression is actually a type (used internally)
//	- scope in which type makes sense
func infer_type(v ast.Expr, scope *scope, index int) (ast.Expr, *scope, bool) {
	switch t := v.(type) {
	case *ast.CompositeLit:
		return t.Type, scope, true
	case *ast.Ident:
		if d := scope.lookup(t.Name); d != nil {
			if d.class == decl_package {
				return ast.NewIdent(t.Name), scope, false
			}
			typ, scope := d.infer_type()
			return typ, scope, d.class == decl_type
		}
	case *ast.UnaryExpr:
		switch t.Op {
		case token.AND:
			// &a makes sense only with values, don't even check for type
			it, s, _ := infer_type(t.X, scope, -1)
			if it == nil {
				break
			}

			e := new(ast.StarExpr)
			e.X = it
			return e, s, false
		case token.ARROW:
			// <-a makes sense only with values
			it, s, _ := infer_type(t.X, scope, -1)
			if it == nil {
				break
			}
			switch index {
			case -1, 0:
				it, s = advance_to_type(chan_predicate, it, s)
				return it.(*ast.ChanType).Value, s, false
			case 1:
				// technically it's a value, but in case of index == 1
				// it is always the last infer operation
				return ast.NewIdent("bool"), g_universe_scope, false
			}
		case token.ADD, token.NOT, token.SUB, token.XOR:
			it, s, _ := infer_type(t.X, scope, -1)
			if it == nil {
				break
			}
			return it, s, false
		}
	case *ast.BinaryExpr:
		switch t.Op {
		case token.EQL, token.NEQ, token.LSS, token.LEQ,
			token.GTR, token.GEQ, token.LOR, token.LAND:
			// logic operations, the result is a bool, always
			return ast.NewIdent("bool"), g_universe_scope, false
		case token.ADD, token.SUB, token.MUL, token.QUO, token.OR,
			token.XOR, token.REM, token.AND, token.AND_NOT:
			// try X, then Y, they should be the same anyway
			it, s, _ := infer_type(t.X, scope, -1)
			if it == nil {
				it, s, _ = infer_type(t.Y, scope, -1)
				if it == nil {
					break
				}
			}
			return it, s, false
		case token.SHL, token.SHR:
			// try only X for shifts, Y is always uint
			it, s, _ := infer_type(t.X, scope, -1)
			if it == nil {
				break
			}
			return it, s, false
		}
	case *ast.IndexExpr:
		// something[another] always returns a value and it works on a value too
		it, s, _ := infer_type(t.X, scope, -1)
		if it == nil {
			break
		}
		it, s = advance_to_type(index_predicate, it, s)
		switch t := it.(type) {
		case *ast.ArrayType:
			return t.Elt, s, false
		case *ast.Ellipsis:
			return t.Elt, s, false
		case *ast.MapType:
			switch index {
			case -1, 0:
				return t.Value, s, false
			case 1:
				return ast.NewIdent("bool"), g_universe_scope, false
			}
		}
	case *ast.SliceExpr:
		// something[start : end] always returns a value
		it, s, _ := infer_type(t.X, scope, -1)
		if it == nil {
			break
		}
		it, s = advance_to_type(index_predicate, it, s)
		switch t := it.(type) {
		case *ast.ArrayType:
			e := new(ast.ArrayType)
			e.Elt = t.Elt
			return e, s, false
		}
	case *ast.StarExpr:
		it, s, is_type := infer_type(t.X, scope, -1)
		if it == nil {
			break
		}
		if is_type {
			// if it's a type, add * modifier, make it a 'pointer of' type
			e := new(ast.StarExpr)
			e.X = it
			return e, s, true
		} else {
			it, s := advance_to_type(star_predicate, it, s)
			if se, ok := it.(*ast.StarExpr); ok {
				return se.X, s, false
			}
		}
	case *ast.CallExpr:
		// this is a function call or a type cast:
		// myFunc(1,2,3) or int16(myvar)
		it, s, is_type := infer_type(t.Fun, scope, -1)
		if it == nil {
			break
		}

		if is_type {
			// a type cast
			return it, scope, false
		} else {
			// it must be a function call or a built-in function
			// first check for built-in
			if ct, ok := it.(*ast.Ident); ok {
				ty, s := check_for_builtin_funcs(ct, t, scope)
				if ty != nil {
					return ty, s, false
				}
			}

			// then check for an ordinary function call
			it, scope = advance_to_type(func_predicate, it, s)
			if ct, ok := it.(*ast.FuncType); ok {
				return func_return_type(ct, index), s, false
			}
		}
	case *ast.ParenExpr:
		it, s, is_type := infer_type(t.X, scope, -1)
		if it == nil {
			break
		}
		return it, s, is_type
	case *ast.SelectorExpr:
		it, s, _ := infer_type(t.X, scope, -1)
		if it == nil {
			break
		}

		if d := type_to_decl(it, s); d != nil {
			c := d.find_child_and_in_embedded(t.Sel.Name)
			if c != nil {
				if c.class == decl_type {
					return t, scope, true
				} else {
					typ, s := c.infer_type()
					return typ, s, false
				}
			}
		}
	case *ast.FuncLit:
		// it's a value, but I think most likely we don't even care, cause we can only
		// call it, and CallExpr uses the type itself to figure out
		return t.Type, scope, false
	case *ast.TypeAssertExpr:
		if t.Type == nil {
			return infer_type(t.X, scope, -1)
		}
		switch index {
		case -1, 0:
			// converting a value to a different type, but return thing is a value
			it, _, _ := infer_type(t.Type, scope, -1)
			return it, scope, false
		case 1:
			return ast.NewIdent("bool"), g_universe_scope, false
		}
	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.Ellipsis,
		*ast.FuncType, *ast.StructType, *ast.InterfaceType:
		return t, scope, true
	default:
		_ = reflect.TypeOf(v)
		//fmt.Println(ty)
	}
	return nil, nil, false
}

// Uses Value, ValueIndex and Scope to infer the type of this
// declaration. Returns the type itself and the scope where this type
// makes sense.
func (d *decl) infer_type() (ast.Expr, *scope) {
	// special case for range vars
	if d.is_rangevar() {
		var scope *scope
		d.typ, scope = infer_range_type(d.value, d.scope, d.value_index)
		return d.typ, scope
	}

	switch d.class {
	case decl_package:
		// package is handled specially in inferType
		return nil, nil
	case decl_type:
		return ast.NewIdent(d.name), d.scope
	}

	// shortcut
	if d.typ != nil && d.value == nil {
		return d.typ, d.scope
	}

	// prevent loops
	if d.is_visited() {
		return nil, nil
	}
	d.set_visited()
	defer d.clear_visited()

	var scope *scope
	d.typ, scope, _ = infer_type(d.value, d.scope, d.value_index)
	return d.typ, scope
}

func (d *decl) type_dealias() *decl {
	if d.is_visited() {
		return nil
	}
	d.set_visited()
	defer d.clear_visited()

	dd := type_to_decl(d.typ, d.scope)
	if dd != nil && dd.is_alias() {
		return dd.type_dealias()
	}
	return dd
}

func (d *decl) find_child(name string) *decl {
	// type aliases don't really have any children on their own, but they
	// point to a different type, let's try to find one
	if d.is_alias() {
		dd := d.type_dealias()
		if dd != nil {
			return dd.find_child(name)
		}

		// note that type alias can also point to a type literal, something like
		// type A = struct { A int }
		// in this case we rely on "advance_to_struct_or_interface" below
	}

	if d.children != nil {
		if c, ok := d.children[name]; ok {
			return c
		}
	}

	decl := advance_to_struct_or_interface(d)
	if decl != nil && decl != d {
		if d.is_visited() {
			return nil
		}
		d.set_visited()
		defer d.clear_visited()

		return decl.find_child(name)
	}
	return nil
}

func (d *decl) find_child_and_in_embedded(name string) *decl {
	if d == nil {
		return nil
	}

	if d.is_alias() {
		dd := d.type_dealias()
		if dd != nil {
			return dd.find_child_and_in_embedded(name)
		}
	}

	if d.is_visited() {
		return nil
	}
	d.set_visited()
	defer d.clear_visited()

	c := d.find_child(name)
	if c == nil {
		for _, e := range d.embedded {
			typedecl := type_to_decl(e, d.scope)
			c = typedecl.find_child_and_in_embedded(name)
			if c != nil {
				break
			}
		}
	}
	return c
}

// Special type inference for range statements.
// [int], [int] := range [string]
// [int], [value] := range [slice or array]
// [key], [value] := range [map]
// [value], [nil] := range [chan]
func infer_range_type(e ast.Expr, sc *scope, valueindex int) (ast.Expr, *scope) {
	t, s, _ := infer_type(e, sc, -1)
	t, s = advance_to_type(range_predicate, t, s)
	if t != nil {
		var t1, t2 ast.Expr
		var s1, s2 *scope
		s1 = s
		s2 = s

		switch t := t.(type) {
		case *ast.Ident:
			// string
			if t.Name == "string" {
				t1 = ast.NewIdent("int")
				t2 = ast.NewIdent("rune")
				s1 = g_universe_scope
				s2 = g_universe_scope
			} else {
				t1, t2 = nil, nil
			}
		case *ast.ArrayType:
			t1 = ast.NewIdent("int")
			s1 = g_universe_scope
			t2 = t.Elt
		case *ast.Ellipsis:
			t1 = ast.NewIdent("int")
			s1 = g_universe_scope
			t2 = t.Elt
		case *ast.MapType:
			t1 = t.Key
			t2 = t.Value
		case *ast.ChanType:
			t1 = t.Value
			t2 = nil
		default:
			t1, t2 = nil, nil
		}

		switch valueindex {
		case 0:
			return t1, s1
		case 1:
			return t2, s2
		}
	}
	return nil, nil
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

func pretty_print_type_expr(out io.Writer, e ast.Expr, canonical_aliases map[string]string) {
	switch t := e.(type) {
	case *ast.StarExpr:
		fmt.Fprintf(out, "*")
		pretty_print_type_expr(out, t.X, canonical_aliases)
	case *ast.Ident:
		if strings.HasPrefix(t.Name, "$") {
			// beautify anonymous types
			switch t.Name[1] {
			case 's':
				fmt.Fprintf(out, "struct")
			case 'i':
				// ok, in most cases anonymous interface is an
				// empty interface, I'll just pretend that
				// it's always true
				fmt.Fprintf(out, "interface{}")
			}
		} else if !*g_debug && strings.HasPrefix(t.Name, "!") {
			// these are full package names for disambiguating and pretty
			// printing packages within packages, e.g.
			// !go/ast!ast vs. !github.com/nsf/my/ast!ast
			// another ugly hack, if people are punished in hell for ugly hacks
			// I'm screwed...
			emarkIdx := strings.LastIndex(t.Name, "!")
			path := t.Name[1:emarkIdx]
			alias := canonical_aliases[path]
			if alias == "" {
				alias = t.Name[emarkIdx+1:]
			}
			fmt.Fprintf(out, alias)
		} else {
			fmt.Fprintf(out, t.Name)
		}
	case *ast.ArrayType:
		al := ""
		if t.Len != nil {
			al = get_array_len(t.Len)
		}
		if al != "" {
			fmt.Fprintf(out, "[%s]", al)
		} else {
			fmt.Fprintf(out, "[]")
		}
		pretty_print_type_expr(out, t.Elt, canonical_aliases)
	case *ast.SelectorExpr:
		pretty_print_type_expr(out, t.X, canonical_aliases)
		fmt.Fprintf(out, ".%s", t.Sel.Name)
	case *ast.FuncType:
		fmt.Fprintf(out, "func(")
		pretty_print_func_field_list(out, t.Params, canonical_aliases)
		fmt.Fprintf(out, ")")

		buf := bytes.NewBuffer(make([]byte, 0, 256))
		nresults := pretty_print_func_field_list(buf, t.Results, canonical_aliases)
		if nresults > 0 {
			results := buf.String()
			if strings.IndexAny(results, ", ") != -1 {
				results = "(" + results + ")"
			}
			fmt.Fprintf(out, " %s", results)
		}
	case *ast.MapType:
		fmt.Fprintf(out, "map[")
		pretty_print_type_expr(out, t.Key, canonical_aliases)
		fmt.Fprintf(out, "]")
		pretty_print_type_expr(out, t.Value, canonical_aliases)
	case *ast.InterfaceType:
		fmt.Fprintf(out, "interface{}")
	case *ast.Ellipsis:
		fmt.Fprintf(out, "...")
		pretty_print_type_expr(out, t.Elt, canonical_aliases)
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
		pretty_print_type_expr(out, t.Value, canonical_aliases)
	case *ast.ParenExpr:
		fmt.Fprintf(out, "(")
		pretty_print_type_expr(out, t.X, canonical_aliases)
		fmt.Fprintf(out, ")")
	case *ast.BadExpr:
		// TODO: probably I should check that in a separate function
		// and simply discard declarations with BadExpr as a part of their
		// type
	default:
		// the element has some weird type, just ignore it
	}
}

func pretty_print_func_field_list(out io.Writer, f *ast.FieldList, canonical_aliases map[string]string) int {
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
		pretty_print_type_expr(out, field.Type, canonical_aliases)

		// ,
		if i != len(f.List)-1 {
			fmt.Fprintf(out, ", ")
		}
	}
	return count
}

func ast_decl_names(d ast.Decl) []*ast.Ident {
	var names []*ast.Ident

	switch t := d.(type) {
	case *ast.GenDecl:
		switch t.Tok {
		case token.CONST:
			c := t.Specs[0].(*ast.ValueSpec)
			names = make([]*ast.Ident, len(c.Names))
			for i, name := range c.Names {
				names[i] = name
			}
		case token.TYPE:
			t := t.Specs[0].(*ast.TypeSpec)
			names = make([]*ast.Ident, 1)
			names[0] = t.Name
		case token.VAR:
			v := t.Specs[0].(*ast.ValueSpec)
			names = make([]*ast.Ident, len(v.Names))
			for i, name := range v.Names {
				names[i] = name
			}
		}
	case *ast.FuncDecl:
		names = make([]*ast.Ident, 1)
		names[0] = t.Name
	}

	return names
}

func ast_decl_values(d ast.Decl) []ast.Expr {
	// TODO: CONST values here too
	switch t := d.(type) {
	case *ast.GenDecl:
		switch t.Tok {
		case token.VAR:
			v := t.Specs[0].(*ast.ValueSpec)
			if v.Values != nil {
				return v.Values
			}
		}
	}
	return nil
}

func ast_decl_split(d ast.Decl) []ast.Decl {
	var decls []ast.Decl
	if t, ok := d.(*ast.GenDecl); ok {
		decls = make([]ast.Decl, len(t.Specs))
		for i, s := range t.Specs {
			decl := new(ast.GenDecl)
			*decl = *t
			decl.Specs = make([]ast.Spec, 1)
			decl.Specs[0] = s
			decls[i] = decl
		}
	} else {
		decls = make([]ast.Decl, 1)
		decls[0] = d
	}
	return decls
}

//-------------------------------------------------------------------------
// decl_pack
//-------------------------------------------------------------------------

type decl_pack struct {
	names  []*ast.Ident
	typ    ast.Expr
	values []ast.Expr
}

type foreach_decl_struct struct {
	decl_pack
	decl ast.Decl
}

func (f *decl_pack) value(i int) ast.Expr {
	if f.values == nil {
		return nil
	}
	if len(f.values) > 1 {
		return f.values[i]
	}
	return f.values[0]
}

func (f *decl_pack) value_index(i int) (v ast.Expr, vi int) {
	// default: nil value
	v = nil
	vi = -1

	if f.values != nil {
		// A = B, if there is only one name, the value is solo too
		if len(f.names) == 1 {
			return f.values[0], -1
		}

		if len(f.values) > 1 {
			// in case if there are multiple values, it's a usual
			// multiassignment
			if i >= len(f.values) {
				i = len(f.values) - 1
			}
			v = f.values[i]
		} else {
			// in case if there is one value, but many names, it's
			// a tuple unpack.. use index here
			v = f.values[0]
			vi = i
		}
	}
	return
}

func (f *decl_pack) type_value_index(i int) (ast.Expr, ast.Expr, int) {
	if f.typ != nil {
		// If there is a type, we don't care about value, just return the type
		// and zero value.
		return f.typ, nil, -1
	}

	// And otherwise we simply return nil type and a valid value for later inferring.
	v, vi := f.value_index(i)
	return nil, v, vi
}

type foreach_decl_func func(data *foreach_decl_struct)

func foreach_decl(decl ast.Decl, do foreach_decl_func) {
	decls := ast_decl_split(decl)
	var data foreach_decl_struct
	for _, decl := range decls {
		if !ast_decl_convertable(decl) {
			continue
		}
		data.names = ast_decl_names(decl)
		data.typ = ast_decl_type(decl)
		data.values = ast_decl_values(decl)
		data.decl = decl

		do(&data)
	}
}

//-------------------------------------------------------------------------
// Built-in declarations
//-------------------------------------------------------------------------

var g_universe_scope = new_scope(nil)

func init() {
	builtin := ast.NewIdent("built-in")

	add_type := func(name string) {
		d := new_decl(name, decl_type, g_universe_scope)
		d.typ = builtin
		g_universe_scope.add_named_decl(d)
	}
	add_type("bool")
	add_type("byte")
	add_type("complex64")
	add_type("complex128")
	add_type("float32")
	add_type("float64")
	add_type("int8")
	add_type("int16")
	add_type("int32")
	add_type("int64")
	add_type("string")
	add_type("uint8")
	add_type("uint16")
	add_type("uint32")
	add_type("uint64")
	add_type("int")
	add_type("uint")
	add_type("uintptr")
	add_type("rune")

	add_const := func(name string) {
		d := new_decl(name, decl_const, g_universe_scope)
		d.typ = builtin
		g_universe_scope.add_named_decl(d)
	}
	add_const("true")
	add_const("false")
	add_const("iota")
	add_const("nil")

	add_func := func(name, typ string) {
		d := new_decl(name, decl_func, g_universe_scope)
		d.typ = ast.NewIdent(typ)
		g_universe_scope.add_named_decl(d)
	}
	add_func("append", "func([]type, ...type) []type")
	add_func("cap", "func(container) int")
	add_func("close", "func(channel)
"""




```