Response:
The user wants a summary of the functionality of the provided Go code snippet. This code is part of the Go compiler's syntax parser. I need to analyze the functions and their roles in parsing Go syntax, particularly related to types, function declarations, struct and interface definitions, and statements.

**Plan:**

1. Identify the main functionalities implemented in the code.
2. Summarize the purpose of each function.
3. Group related functions together to explain specific parsing capabilities.
这是 `go/src/cmd/compile/internal/syntax/parser.go` 文件的一部分，主要负责 Go 语言源代码的**类型 (Type)** 相关的语法分析。

**归纳一下它的功能：**

这段代码的核心功能是解析 Go 语言中各种类型的语法结构，并将它们转换成抽象语法树 (AST) 中的 `Expr` 节点。它涵盖了基础类型、复合类型（数组、切片、指针、Map、Channel、结构体、接口、函数类型）以及类型参数等。

**具体功能点：**

1. **解析各种类型表达式:**  这段代码包含了多个用于解析不同类型表达式的函数，例如 `type_`, `typeOrNil`, `arrayType`, `sliceType`, `chanElem`, `mapType`, `structType`, `interfaceType`, `funcType` 等。这些函数能够识别并解析 Go 语言中所有合法的类型定义。
2. **处理类型名称和限定标识符:**  `qualifiedName` 函数用于解析类型名称，它可以处理简单的标识符，也可以处理带有包路径的限定标识符 (e.g., `pkg.TypeName`)。
3. **解析函数类型:** `funcType` 函数专门用于解析函数类型，包括参数列表和返回值列表，以及类型参数列表（泛型）。
4. **解析结构体类型:** `structType` 函数用于解析结构体定义，包括字段声明和可选的标签 (tag)。
5. **解析接口类型:** `interfaceType` 函数用于解析接口定义，包括方法声明和嵌入式类型。
6. **解析数组和切片类型:** `arrayType` 和 `sliceType` 函数分别用于解析数组和切片类型的定义。
7. **解析指针类型:**  通过 `_Star` token 和 `newIndirect` 函数来解析指针类型。
8. **解析 Map 类型:** `mapType` 函数用于解析 Map 类型的定义。
9. **解析 Channel 类型:**  通过 `_Chan` 和 `_Arrow` token 以及 `chanElem` 函数来解析 Channel 类型的定义。
10. **处理类型实例化:** `typeInstance` 函数用于解析类型实例化，例如 `T[int]`。
11. **处理类型参数:** `funcType` 和 `paramList` 函数协作处理函数和方法中的类型参数声明。
12. **错误处理和同步:**  代码中包含 `syntaxError` 和 `advance` 等函数，用于在解析过程中发现语法错误并尝试同步解析器，以便继续处理后续代码。

**Go 代码示例 (展示部分功能):**

假设有以下 Go 代码作为输入：

```go
package main

type MyInt int
type MyArray [10]int
type MySlice []string
type MyMap map[string]int
type MyChan chan int
type MyStruct struct {
	Name string `json:"name"`
	Age  int
}
type MyInterface interface {
	Method1()
	Method2(int)
}
type MyFunc func(int) string
type GenericFunc[T any](T)

func main() {
	var a MyInt
	var b MyArray
	var c MySlice
	var d MyMap
	var e MyChan
	var f MyStruct
	var g MyInterface
	var h MyFunc
	var i GenericFunc[int]
	println(a, b, c, d, e, f, g, h, i)
}
```

**推理：**

当解析器遇到 `type MyInt int` 时，`typeDecl` 函数会调用 `p.type_()` 来解析 `int` 这个类型。
当解析器遇到 `type MyArray [10]int` 时，`arrayType` 函数会被调用，它会解析 `10` 作为数组长度，并调用 `p.type_()` 解析 `int` 作为元素类型。
当解析器遇到 `type MySlice []string` 时，`sliceType` 函数会被调用，它会调用 `p.type_()` 解析 `string` 作为元素类型。
当解析器遇到 `type MyMap map[string]int` 时，`mapType` 函数会被调用，它会解析 `string` 作为键类型，`int` 作为值类型。
当解析器遇到 `type MyChan chan int` 时，会根据 `_Chan` token 调用相应的代码，并使用 `chanElem` 解析 `int`。
当解析器遇到 `type MyStruct struct { ... }` 时，`structType` 函数会被调用，它会解析结构体内部的字段声明。
当解析器遇到 `type MyInterface interface { ... }` 时，`interfaceType` 函数会被调用，它会解析接口内部的方法声明。
当解析器遇到 `type MyFunc func(int) string` 时，`funcType` 函数会被调用，它会解析参数列表 `(int)` 和返回值类型 `string`。
当解析器遇到 `type GenericFunc[T any](T)` 时，`funcType` 会解析类型参数 `[T any]` 和函数签名 `(T)`。

**假设的输入与输出（针对 `arrayType` 函数）：**

**假设输入 token 流:** `_Lbrack`, `_Literal` (值 "10"), `_Rbrack`, `_Name` (值 "int")

**`arrayType` 函数调用流程 (简化):**

1. 进入 `arrayType` 函数，`pos` 指向 `_Lbrack`。
2. `p.got(_DotDotDot)` 返回 `false`。
3. `p.xnest++`。
4. `p.expr()` 被调用，解析 `_Literal` ("10")，返回一个表示常量 10 的 `Expr` 节点。
5. `p.xnest--`。
6. `p.want(_Rbrack)` 消耗 `_Rbrack` token。
7. 创建一个新的 `ArrayType` 节点 `t`。
8. `t.pos` 被设置为 `pos`。
9. `t.Len` 被设置为解析得到的常量 10 的 `Expr` 节点。
10. `p.type_()` 被调用，解析 `_Name` ("int")，返回表示 `int` 类型的 `Expr` 节点。
11. `t.Elem` 被设置为表示 `int` 类型的 `Expr` 节点。
12. 返回 `t`。

**使用者易犯错的点（没有在提供的代码片段中直接体现，但与类型定义相关）：**

*   **结构体字段类型声明顺序:**  在结构体中，字段名必须在类型之前。写成 `int Age` 是错误的，应该写成 `Age int`。
*   **Map 类型的键类型限制:**  Map 的键类型必须是可比较的类型。尝试使用切片或函数作为键类型会导致编译错误。
*   **Channel 的方向性:**  创建只发送或只接收的 channel 后，尝试进行反方向的操作会导致编译错误。
*   **接口的实现:**  没有显式声明，只要类型实现了接口的所有方法，就被认为是实现了该接口。容易忽略某些方法导致类型没有正确实现接口。

这段代码片段主要关注语法分析阶段，不涉及具体的类型检查和语义分析，因此没有直接处理命令行参数。命令行参数的处理发生在编译器的其他阶段。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/syntax/parser.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
efer p.trace("type_")()
	}

	typ := p.typeOrNil()
	if typ == nil {
		typ = p.badExpr()
		p.syntaxError("expected type")
		p.advance(_Comma, _Colon, _Semi, _Rparen, _Rbrack, _Rbrace)
	}

	return typ
}

func newIndirect(pos Pos, typ Expr) Expr {
	o := new(Operation)
	o.pos = pos
	o.Op = Mul
	o.X = typ
	return o
}

// typeOrNil is like type_ but it returns nil if there was no type
// instead of reporting an error.
//
//	Type     = TypeName | TypeLit | "(" Type ")" .
//	TypeName = identifier | QualifiedIdent .
//	TypeLit  = ArrayType | StructType | PointerType | FunctionType | InterfaceType |
//		      SliceType | MapType | Channel_Type .
func (p *parser) typeOrNil() Expr {
	if trace {
		defer p.trace("typeOrNil")()
	}

	pos := p.pos()
	switch p.tok {
	case _Star:
		// ptrtype
		p.next()
		return newIndirect(pos, p.type_())

	case _Arrow:
		// recvchantype
		p.next()
		p.want(_Chan)
		t := new(ChanType)
		t.pos = pos
		t.Dir = RecvOnly
		t.Elem = p.chanElem()
		return t

	case _Func:
		// fntype
		p.next()
		_, t := p.funcType("function type")
		return t

	case _Lbrack:
		// '[' oexpr ']' ntype
		// '[' _DotDotDot ']' ntype
		p.next()
		if p.got(_Rbrack) {
			return p.sliceType(pos)
		}
		return p.arrayType(pos, nil)

	case _Chan:
		// _Chan non_recvchantype
		// _Chan _Comm ntype
		p.next()
		t := new(ChanType)
		t.pos = pos
		if p.got(_Arrow) {
			t.Dir = SendOnly
		}
		t.Elem = p.chanElem()
		return t

	case _Map:
		// _Map '[' ntype ']' ntype
		p.next()
		p.want(_Lbrack)
		t := new(MapType)
		t.pos = pos
		t.Key = p.type_()
		p.want(_Rbrack)
		t.Value = p.type_()
		return t

	case _Struct:
		return p.structType()

	case _Interface:
		return p.interfaceType()

	case _Name:
		return p.qualifiedName(nil)

	case _Lparen:
		p.next()
		t := p.type_()
		p.want(_Rparen)
		// The parser doesn't keep unnecessary parentheses.
		// Set the flag below to keep them, for testing
		// (see e.g. tests for go.dev/issue/68639).
		const keep_parens = false
		if keep_parens {
			px := new(ParenExpr)
			px.pos = pos
			px.X = t
			t = px
		}
		return t
	}

	return nil
}

func (p *parser) typeInstance(typ Expr) Expr {
	if trace {
		defer p.trace("typeInstance")()
	}

	pos := p.pos()
	p.want(_Lbrack)
	x := new(IndexExpr)
	x.pos = pos
	x.X = typ
	if p.tok == _Rbrack {
		p.syntaxError("expected type argument list")
		x.Index = p.badExpr()
	} else {
		x.Index, _ = p.typeList(true)
	}
	p.want(_Rbrack)
	return x
}

// If context != "", type parameters are not permitted.
func (p *parser) funcType(context string) ([]*Field, *FuncType) {
	if trace {
		defer p.trace("funcType")()
	}

	typ := new(FuncType)
	typ.pos = p.pos()

	var tparamList []*Field
	if p.got(_Lbrack) {
		if context != "" {
			// accept but complain
			p.syntaxErrorAt(typ.pos, context+" must have no type parameters")
		}
		if p.tok == _Rbrack {
			p.syntaxError("empty type parameter list")
			p.next()
		} else {
			tparamList = p.paramList(nil, nil, _Rbrack, true)
		}
	}

	p.want(_Lparen)
	typ.ParamList = p.paramList(nil, nil, _Rparen, false)
	typ.ResultList = p.funcResult()

	return tparamList, typ
}

// "[" has already been consumed, and pos is its position.
// If len != nil it is the already consumed array length.
func (p *parser) arrayType(pos Pos, len Expr) Expr {
	if trace {
		defer p.trace("arrayType")()
	}

	if len == nil && !p.got(_DotDotDot) {
		p.xnest++
		len = p.expr()
		p.xnest--
	}
	if p.tok == _Comma {
		// Trailing commas are accepted in type parameter
		// lists but not in array type declarations.
		// Accept for better error handling but complain.
		p.syntaxError("unexpected comma; expected ]")
		p.next()
	}
	p.want(_Rbrack)
	t := new(ArrayType)
	t.pos = pos
	t.Len = len
	t.Elem = p.type_()
	return t
}

// "[" and "]" have already been consumed, and pos is the position of "[".
func (p *parser) sliceType(pos Pos) Expr {
	t := new(SliceType)
	t.pos = pos
	t.Elem = p.type_()
	return t
}

func (p *parser) chanElem() Expr {
	if trace {
		defer p.trace("chanElem")()
	}

	typ := p.typeOrNil()
	if typ == nil {
		typ = p.badExpr()
		p.syntaxError("missing channel element type")
		// assume element type is simply absent - don't advance
	}

	return typ
}

// StructType = "struct" "{" { FieldDecl ";" } "}" .
func (p *parser) structType() *StructType {
	if trace {
		defer p.trace("structType")()
	}

	typ := new(StructType)
	typ.pos = p.pos()

	p.want(_Struct)
	p.want(_Lbrace)
	p.list("struct type", _Semi, _Rbrace, func() bool {
		p.fieldDecl(typ)
		return false
	})

	return typ
}

// InterfaceType = "interface" "{" { ( MethodDecl | EmbeddedElem ) ";" } "}" .
func (p *parser) interfaceType() *InterfaceType {
	if trace {
		defer p.trace("interfaceType")()
	}

	typ := new(InterfaceType)
	typ.pos = p.pos()

	p.want(_Interface)
	p.want(_Lbrace)
	p.list("interface type", _Semi, _Rbrace, func() bool {
		var f *Field
		if p.tok == _Name {
			f = p.methodDecl()
		}
		if f == nil || f.Name == nil {
			f = p.embeddedElem(f)
		}
		typ.MethodList = append(typ.MethodList, f)
		return false
	})

	return typ
}

// Result = Parameters | Type .
func (p *parser) funcResult() []*Field {
	if trace {
		defer p.trace("funcResult")()
	}

	if p.got(_Lparen) {
		return p.paramList(nil, nil, _Rparen, false)
	}

	pos := p.pos()
	if typ := p.typeOrNil(); typ != nil {
		f := new(Field)
		f.pos = pos
		f.Type = typ
		return []*Field{f}
	}

	return nil
}

func (p *parser) addField(styp *StructType, pos Pos, name *Name, typ Expr, tag *BasicLit) {
	if tag != nil {
		for i := len(styp.FieldList) - len(styp.TagList); i > 0; i-- {
			styp.TagList = append(styp.TagList, nil)
		}
		styp.TagList = append(styp.TagList, tag)
	}

	f := new(Field)
	f.pos = pos
	f.Name = name
	f.Type = typ
	styp.FieldList = append(styp.FieldList, f)

	if debug && tag != nil && len(styp.FieldList) != len(styp.TagList) {
		panic("inconsistent struct field list")
	}
}

// FieldDecl      = (IdentifierList Type | AnonymousField) [ Tag ] .
// AnonymousField = [ "*" ] TypeName .
// Tag            = string_lit .
func (p *parser) fieldDecl(styp *StructType) {
	if trace {
		defer p.trace("fieldDecl")()
	}

	pos := p.pos()
	switch p.tok {
	case _Name:
		name := p.name()
		if p.tok == _Dot || p.tok == _Literal || p.tok == _Semi || p.tok == _Rbrace {
			// embedded type
			typ := p.qualifiedName(name)
			tag := p.oliteral()
			p.addField(styp, pos, nil, typ, tag)
			break
		}

		// name1, name2, ... Type [ tag ]
		names := p.nameList(name)
		var typ Expr

		// Careful dance: We don't know if we have an embedded instantiated
		// type T[P1, P2, ...] or a field T of array/slice type [P]E or []E.
		if len(names) == 1 && p.tok == _Lbrack {
			typ = p.arrayOrTArgs()
			if typ, ok := typ.(*IndexExpr); ok {
				// embedded type T[P1, P2, ...]
				typ.X = name // name == names[0]
				tag := p.oliteral()
				p.addField(styp, pos, nil, typ, tag)
				break
			}
		} else {
			// T P
			typ = p.type_()
		}

		tag := p.oliteral()

		for _, name := range names {
			p.addField(styp, name.Pos(), name, typ, tag)
		}

	case _Star:
		p.next()
		var typ Expr
		if p.tok == _Lparen {
			// *(T)
			p.syntaxError("cannot parenthesize embedded type")
			p.next()
			typ = p.qualifiedName(nil)
			p.got(_Rparen) // no need to complain if missing
		} else {
			// *T
			typ = p.qualifiedName(nil)
		}
		tag := p.oliteral()
		p.addField(styp, pos, nil, newIndirect(pos, typ), tag)

	case _Lparen:
		p.syntaxError("cannot parenthesize embedded type")
		p.next()
		var typ Expr
		if p.tok == _Star {
			// (*T)
			pos := p.pos()
			p.next()
			typ = newIndirect(pos, p.qualifiedName(nil))
		} else {
			// (T)
			typ = p.qualifiedName(nil)
		}
		p.got(_Rparen) // no need to complain if missing
		tag := p.oliteral()
		p.addField(styp, pos, nil, typ, tag)

	default:
		p.syntaxError("expected field name or embedded type")
		p.advance(_Semi, _Rbrace)
	}
}

func (p *parser) arrayOrTArgs() Expr {
	if trace {
		defer p.trace("arrayOrTArgs")()
	}

	pos := p.pos()
	p.want(_Lbrack)
	if p.got(_Rbrack) {
		return p.sliceType(pos)
	}

	// x [n]E or x[n,], x[n1, n2], ...
	n, comma := p.typeList(false)
	p.want(_Rbrack)
	if !comma {
		if elem := p.typeOrNil(); elem != nil {
			// x [n]E
			t := new(ArrayType)
			t.pos = pos
			t.Len = n
			t.Elem = elem
			return t
		}
	}

	// x[n,], x[n1, n2], ...
	t := new(IndexExpr)
	t.pos = pos
	// t.X will be filled in by caller
	t.Index = n
	return t
}

func (p *parser) oliteral() *BasicLit {
	if p.tok == _Literal {
		b := new(BasicLit)
		b.pos = p.pos()
		b.Value = p.lit
		b.Kind = p.kind
		b.Bad = p.bad
		p.next()
		return b
	}
	return nil
}

// MethodSpec        = MethodName Signature | InterfaceTypeName .
// MethodName        = identifier .
// InterfaceTypeName = TypeName .
func (p *parser) methodDecl() *Field {
	if trace {
		defer p.trace("methodDecl")()
	}

	f := new(Field)
	f.pos = p.pos()
	name := p.name()

	const context = "interface method"

	switch p.tok {
	case _Lparen:
		// method
		f.Name = name
		_, f.Type = p.funcType(context)

	case _Lbrack:
		// Careful dance: We don't know if we have a generic method m[T C](x T)
		// or an embedded instantiated type T[P1, P2] (we accept generic methods
		// for generality and robustness of parsing but complain with an error).
		pos := p.pos()
		p.next()

		// Empty type parameter or argument lists are not permitted.
		// Treat as if [] were absent.
		if p.tok == _Rbrack {
			// name[]
			pos := p.pos()
			p.next()
			if p.tok == _Lparen {
				// name[](
				p.errorAt(pos, "empty type parameter list")
				f.Name = name
				_, f.Type = p.funcType(context)
			} else {
				p.errorAt(pos, "empty type argument list")
				f.Type = name
			}
			break
		}

		// A type argument list looks like a parameter list with only
		// types. Parse a parameter list and decide afterwards.
		list := p.paramList(nil, nil, _Rbrack, false)
		if len(list) == 0 {
			// The type parameter list is not [] but we got nothing
			// due to other errors (reported by paramList). Treat
			// as if [] were absent.
			if p.tok == _Lparen {
				f.Name = name
				_, f.Type = p.funcType(context)
			} else {
				f.Type = name
			}
			break
		}

		// len(list) > 0
		if list[0].Name != nil {
			// generic method
			f.Name = name
			_, f.Type = p.funcType(context)
			p.errorAt(pos, "interface method must have no type parameters")
			break
		}

		// embedded instantiated type
		t := new(IndexExpr)
		t.pos = pos
		t.X = name
		if len(list) == 1 {
			t.Index = list[0].Type
		} else {
			// len(list) > 1
			l := new(ListExpr)
			l.pos = list[0].Pos()
			l.ElemList = make([]Expr, len(list))
			for i := range list {
				l.ElemList[i] = list[i].Type
			}
			t.Index = l
		}
		f.Type = t

	default:
		// embedded type
		f.Type = p.qualifiedName(name)
	}

	return f
}

// EmbeddedElem = MethodSpec | EmbeddedTerm { "|" EmbeddedTerm } .
func (p *parser) embeddedElem(f *Field) *Field {
	if trace {
		defer p.trace("embeddedElem")()
	}

	if f == nil {
		f = new(Field)
		f.pos = p.pos()
		f.Type = p.embeddedTerm()
	}

	for p.tok == _Operator && p.op == Or {
		t := new(Operation)
		t.pos = p.pos()
		t.Op = Or
		p.next()
		t.X = f.Type
		t.Y = p.embeddedTerm()
		f.Type = t
	}

	return f
}

// EmbeddedTerm = [ "~" ] Type .
func (p *parser) embeddedTerm() Expr {
	if trace {
		defer p.trace("embeddedTerm")()
	}

	if p.tok == _Operator && p.op == Tilde {
		t := new(Operation)
		t.pos = p.pos()
		t.Op = Tilde
		p.next()
		t.X = p.type_()
		return t
	}

	t := p.typeOrNil()
	if t == nil {
		t = p.badExpr()
		p.syntaxError("expected ~ term or type")
		p.advance(_Operator, _Semi, _Rparen, _Rbrack, _Rbrace)
	}

	return t
}

// ParameterDecl = [ IdentifierList ] [ "..." ] Type .
func (p *parser) paramDeclOrNil(name *Name, follow token) *Field {
	if trace {
		defer p.trace("paramDeclOrNil")()
	}

	// type set notation is ok in type parameter lists
	typeSetsOk := follow == _Rbrack

	pos := p.pos()
	if name != nil {
		pos = name.pos
	} else if typeSetsOk && p.tok == _Operator && p.op == Tilde {
		// "~" ...
		return p.embeddedElem(nil)
	}

	f := new(Field)
	f.pos = pos

	if p.tok == _Name || name != nil {
		// name
		if name == nil {
			name = p.name()
		}

		if p.tok == _Lbrack {
			// name "[" ...
			f.Type = p.arrayOrTArgs()
			if typ, ok := f.Type.(*IndexExpr); ok {
				// name "[" ... "]"
				typ.X = name
			} else {
				// name "[" n "]" E
				f.Name = name
			}
			if typeSetsOk && p.tok == _Operator && p.op == Or {
				// name "[" ... "]" "|" ...
				// name "[" n "]" E "|" ...
				f = p.embeddedElem(f)
			}
			return f
		}

		if p.tok == _Dot {
			// name "." ...
			f.Type = p.qualifiedName(name)
			if typeSetsOk && p.tok == _Operator && p.op == Or {
				// name "." name "|" ...
				f = p.embeddedElem(f)
			}
			return f
		}

		if typeSetsOk && p.tok == _Operator && p.op == Or {
			// name "|" ...
			f.Type = name
			return p.embeddedElem(f)
		}

		f.Name = name
	}

	if p.tok == _DotDotDot {
		// [name] "..." ...
		t := new(DotsType)
		t.pos = p.pos()
		p.next()
		t.Elem = p.typeOrNil()
		if t.Elem == nil {
			t.Elem = p.badExpr()
			p.syntaxError("... is missing type")
		}
		f.Type = t
		return f
	}

	if typeSetsOk && p.tok == _Operator && p.op == Tilde {
		// [name] "~" ...
		f.Type = p.embeddedElem(nil).Type
		return f
	}

	f.Type = p.typeOrNil()
	if typeSetsOk && p.tok == _Operator && p.op == Or && f.Type != nil {
		// [name] type "|"
		f = p.embeddedElem(f)
	}
	if f.Name != nil || f.Type != nil {
		return f
	}

	p.syntaxError("expected " + tokstring(follow))
	p.advance(_Comma, follow)
	return nil
}

// Parameters    = "(" [ ParameterList [ "," ] ] ")" .
// ParameterList = ParameterDecl { "," ParameterDecl } .
// "(" or "[" has already been consumed.
// If name != nil, it is the first name after "(" or "[".
// If typ != nil, name must be != nil, and (name, typ) is the first field in the list.
// In the result list, either all fields have a name, or no field has a name.
func (p *parser) paramList(name *Name, typ Expr, close token, requireNames bool) (list []*Field) {
	if trace {
		defer p.trace("paramList")()
	}

	// p.list won't invoke its function argument if we're at the end of the
	// parameter list. If we have a complete field, handle this case here.
	if name != nil && typ != nil && p.tok == close {
		p.next()
		par := new(Field)
		par.pos = name.pos
		par.Name = name
		par.Type = typ
		return []*Field{par}
	}

	var named int // number of parameters that have an explicit name and type
	var typed int // number of parameters that have an explicit type
	end := p.list("parameter list", _Comma, close, func() bool {
		var par *Field
		if typ != nil {
			if debug && name == nil {
				panic("initial type provided without name")
			}
			par = new(Field)
			par.pos = name.pos
			par.Name = name
			par.Type = typ
		} else {
			par = p.paramDeclOrNil(name, close)
		}
		name = nil // 1st name was consumed if present
		typ = nil  // 1st type was consumed if present
		if par != nil {
			if debug && par.Name == nil && par.Type == nil {
				panic("parameter without name or type")
			}
			if par.Name != nil && par.Type != nil {
				named++
			}
			if par.Type != nil {
				typed++
			}
			list = append(list, par)
		}
		return false
	})

	if len(list) == 0 {
		return
	}

	// distribute parameter types (len(list) > 0)
	if named == 0 && !requireNames {
		// all unnamed and we're not in a type parameter list => found names are named types
		for _, par := range list {
			if typ := par.Name; typ != nil {
				par.Type = typ
				par.Name = nil
			}
		}
	} else if named != len(list) {
		// some named or we're in a type parameter list => all must be named
		var errPos Pos // left-most error position (or unknown)
		var typ Expr   // current type (from right to left)
		for i := len(list) - 1; i >= 0; i-- {
			par := list[i]
			if par.Type != nil {
				typ = par.Type
				if par.Name == nil {
					errPos = StartPos(typ)
					par.Name = NewName(errPos, "_")
				}
			} else if typ != nil {
				par.Type = typ
			} else {
				// par.Type == nil && typ == nil => we only have a par.Name
				errPos = par.Name.Pos()
				t := p.badExpr()
				t.pos = errPos // correct position
				par.Type = t
			}
		}
		if errPos.IsKnown() {
			// Not all parameters are named because named != len(list).
			// If named == typed, there must be parameters that have no types.
			// They must be at the end of the parameter list, otherwise types
			// would have been filled in by the right-to-left sweep above and
			// there would be no error.
			// If requireNames is set, the parameter list is a type parameter
			// list.
			var msg string
			if named == typed {
				errPos = end // position error at closing token ) or ]
				if requireNames {
					msg = "missing type constraint"
				} else {
					msg = "missing parameter type"
				}
			} else {
				if requireNames {
					msg = "missing type parameter name"
					// go.dev/issue/60812
					if len(list) == 1 {
						msg += " or invalid array length"
					}
				} else {
					msg = "missing parameter name"
				}
			}
			p.syntaxErrorAt(errPos, msg)
		}
	}

	return
}

func (p *parser) badExpr() *BadExpr {
	b := new(BadExpr)
	b.pos = p.pos()
	return b
}

// ----------------------------------------------------------------------------
// Statements

// SimpleStmt = EmptyStmt | ExpressionStmt | SendStmt | IncDecStmt | Assignment | ShortVarDecl .
func (p *parser) simpleStmt(lhs Expr, keyword token) SimpleStmt {
	if trace {
		defer p.trace("simpleStmt")()
	}

	if keyword == _For && p.tok == _Range {
		// _Range expr
		if debug && lhs != nil {
			panic("invalid call of simpleStmt")
		}
		return p.newRangeClause(nil, false)
	}

	if lhs == nil {
		lhs = p.exprList()
	}

	if _, ok := lhs.(*ListExpr); !ok && p.tok != _Assign && p.tok != _Define {
		// expr
		pos := p.pos()
		switch p.tok {
		case _AssignOp:
			// lhs op= rhs
			op := p.op
			p.next()
			return p.newAssignStmt(pos, op, lhs, p.expr())

		case _IncOp:
			// lhs++ or lhs--
			op := p.op
			p.next()
			return p.newAssignStmt(pos, op, lhs, nil)

		case _Arrow:
			// lhs <- rhs
			s := new(SendStmt)
			s.pos = pos
			p.next()
			s.Chan = lhs
			s.Value = p.expr()
			return s

		default:
			// expr
			s := new(ExprStmt)
			s.pos = lhs.Pos()
			s.X = lhs
			return s
		}
	}

	// expr_list
	switch p.tok {
	case _Assign, _Define:
		pos := p.pos()
		var op Operator
		if p.tok == _Define {
			op = Def
		}
		p.next()

		if keyword == _For && p.tok == _Range {
			// expr_list op= _Range expr
			return p.newRangeClause(lhs, op == Def)
		}

		// expr_list op= expr_list
		rhs := p.exprList()

		if x, ok := rhs.(*TypeSwitchGuard); ok && keyword == _Switch && op == Def {
			if lhs, ok := lhs.(*Name); ok {
				// switch … lhs := rhs.(type)
				x.Lhs = lhs
				s := new(ExprStmt)
				s.pos = x.Pos()
				s.X = x
				return s
			}
		}

		return p.newAssignStmt(pos, op, lhs, rhs)

	default:
		p.syntaxError("expected := or = or comma")
		p.advance(_Semi, _Rbrace)
		// make the best of what we have
		if x, ok := lhs.(*ListExpr); ok {
			lhs = x.ElemList[0]
		}
		s := new(ExprStmt)
		s.pos = lhs.Pos()
		s.X = lhs
		return s
	}
}

func (p *parser) newRangeClause(lhs Expr, def bool) *RangeClause {
	r := new(RangeClause)
	r.pos = p.pos()
	p.next() // consume _Range
	r.Lhs = lhs
	r.Def = def
	r.X = p.expr()
	return r
}

func (p *parser) newAssignStmt(pos Pos, op Operator, lhs, rhs Expr) *AssignStmt {
	a := new(AssignStmt)
	a.pos = pos
	a.Op = op
	a.Lhs = lhs
	a.Rhs = rhs
	return a
}

func (p *parser) labeledStmtOrNil(label *Name) Stmt {
	if trace {
		defer p.trace("labeledStmt")()
	}

	s := new(LabeledStmt)
	s.pos = p.pos()
	s.Label = label

	p.want(_Colon)

	if p.tok == _Rbrace {
		// We expect a statement (incl. an empty statement), which must be
		// terminated by a semicolon. Because semicolons may be omitted before
		// an _Rbrace, seeing an _Rbrace implies an empty statement.
		e := new(EmptyStmt)
		e.pos = p.pos()
		s.Stmt = e
		return s
	}

	s.Stmt = p.stmtOrNil()
	if s.Stmt != nil {
		return s
	}

	// report error at line of ':' token
	p.syntaxErrorAt(s.pos, "missing statement after label")
	// we are already at the end of the labeled statement - no need to advance
	return nil // avoids follow-on errors (see e.g., fixedbugs/bug274.go)
}

// context must be a non-empty string unless we know that p.tok == _Lbrace.
func (p *parser) blockStmt(context string) *BlockStmt {
	if trace {
		defer p.trace("blockStmt")()
	}

	s := new(BlockStmt)
	s.pos = p.pos()

	// people coming from C may forget that braces are mandatory in Go
	if !p.got(_Lbrace) {
		p.syntaxError("expected { after " + context)
		p.advance(_Name, _Rbrace)
		s.Rbrace = p.pos() // in case we found "}"
		if p.got(_Rbrace) {
			return s
		}
	}

	s.List = p.stmtList()
	s.Rbrace = p.pos()
	p.want(_Rbrace)

	return s
}

func (p *parser) declStmt(f func(*Group) Decl) *DeclStmt {
	if trace {
		defer p.trace("declStmt")()
	}

	s := new(DeclStmt)
	s.pos = p.pos()

	p.next() // _Const, _Type, or _Var
	s.DeclList = p.appendGroup(nil, f)

	return s
}

func (p *parser) forStmt() Stmt {
	if trace {
		defer p.trace("forStmt")()
	}

	s := new(ForStmt)
	s.pos = p.pos()

	s.Init, s.Cond, s.Post = p.header(_For)
	s.Body = p.blockStmt("for clause")

	return s
}

func (p *parser) header(keyword token) (init SimpleStmt, cond Expr, post SimpleStmt) {
	p.want(keyword)

	if p.tok == _Lbrace {
		if keyword == _If {
			p.syntaxError("missing condition in if statement")
			cond = p.badExpr()
		}
		return
	}
	// p.tok != _Lbrace

	outer := p.xnest
	p.xnest = -1

	if p.tok != _Semi {
		// accept potential varDecl but complain
		if p.got(_Var) {
			p.syntaxError(fmt.Sprintf("var declaration not allowed in %s initializer", keyword.String()))
		}
		init = p.simpleStmt(nil, keyword)
		// If we have a range clause, we are done (can only happen for keyword == _For).
		if _, ok := init.(*RangeClause); ok {
			p.xnest = outer
			return
		}
	}

	var condStmt SimpleStmt
	var semi struct {
		pos Pos
		lit string // valid if pos.IsKnown()
	}
	if p.tok != _Lbrace {
		if p.tok == _Semi {
			semi.pos = p.pos()
			semi.lit = p.lit
			p.next()
		} else {
			// asking for a '{' rather than a ';' here leads to a better error message
			p.want(_Lbrace)
			if p.tok != _Lbrace {
				p.advance(_Lbrace, _Rbrace) // for better synchronization (e.g., go.dev/issue/22581)
			}
		}
		if keyword == _For {
			if p.tok != _Semi {
				if p.tok == _Lbrace {
					p.syntaxError("expected for loop condition")
					goto done
				}
				condStmt = p.simpleStmt(nil, 0 /* range not permitted */)
			}
			p.want(_Semi)
			if p.tok != _Lbrace {
				post = p.simpleStmt(nil, 0 /* range not permitted */)
				if a, _ := post.(*AssignStmt); a != nil && a.Op == Def {
					p.syntaxErrorAt(a.Pos(), "cannot declare in post statement of for loop")
				}
			}
		} else if p.tok != _Lbrace {
			condStmt = p.simpleStmt(nil, keyword)
		}
	} else {
		condStmt = init
		init = nil
	}

done:
	// unpack condStmt
	switch s := condStmt.(type) {
	case nil:
		if keyword == _If && semi.pos.IsKnown() {
			if semi.lit != "semicolon" {
				p.syntaxErrorAt(semi.pos, fmt.Sprintf("unexpected %s, expected { after if clause", semi.lit))
			} else {
				p.syntaxErrorAt(semi.pos, "missing condition in if statement")
			}
			b := new(BadExpr)
			b.pos = semi.pos
			cond = b
		}
	case *ExprStmt:
		cond = s.X
	default:
		// A common syntax error is to write '=' instead of '==',
		// which turns an expression into an assignment. Provide
		// a more explicit error message in that case to prevent
		// further confusion.
		var str string
		if as, ok := s.(*AssignStmt); ok && as.Op == 0 {
			// Emphasize complex Lhs and Rhs of assignment with parentheses to highlight '='.
			str = "assignment " + emphasize(as.Lhs) + " = " + emphasize(as.Rhs)
		} else {
			str = String(s)
		}
		p.syntaxErrorAt(s.Pos(), fmt.Sprintf("cannot use %s as value", str))
	}

	p.xnest = outer
	return
}

// emphasize returns a string representation of x, with (top-level)
// binary expressions emphasized by enclosing them in parentheses.
func emphasize(x Expr) string {
	s := String(x)
	if op, _ := x.(*Operation); op != nil && op.Y != nil {
		// binary expression
		return "(" + s + ")"
	}
	return s
}

func (p *parser) ifStmt() *IfStmt {
	if trace {
		defer p.trace("ifStmt")()
	}

	s := new(IfStmt)
	s.pos = p.pos()

	s.Init, s.Cond, _ = p.header(_If)
	s.Then = p.blockStmt("if clause")

	if p.got(_Else) {
		switch p.tok {
		case _If:
			s.Else = p.ifStmt()
		case _Lbrace:
			s.Else = p.blockStmt("")
		default:
			p.syntaxError("else must be followed by if or statement block")
			p.advance(_Name, _Rbrace)
		}
	}

	return s
}

func (p *parser) switchStmt() *SwitchStmt {
	if trace {
		defer p.trace("switchStmt")()
	}

	s := new(SwitchStmt)
	s.pos = p.pos()

	s.Init, s.Tag, _ = p.header(_Switch)

	if !p.got(_Lbrace) {
		p.syntaxError("missing { after switch clause")
		p.advance(_Case, _Default, _Rbrace)
	}
	for p.tok != _EOF && p.tok != _Rbrace {
		s.Body = append(s.Body, p.caseClause())
	}
	s.Rbrace = p.pos()
	p.want(_Rbrace)

	return s
}

func (p *parser) selectStmt() *SelectStmt {
	if trace {
		defer p.trace("selectStmt")()
	}

	s := new(SelectStmt)
	s.pos = p.pos()

	p.want(_Select)
	if !p.got(_Lbrace) {
		p.syntaxError("missing { after select clause")
		p.advance(_Case, _Default, _Rbrace)
	}
	for p.tok != _EOF && p.tok != _Rbrace {
		s.Body = append(s.Body, p.commClause())
	}
	s.Rbrace = p.pos()
	p.want(_Rbrace)

	return s
}

func (p *parser) caseClause() *CaseClause {
	if trace {
		defer p.trace("caseClause")()
	}

	c := new(CaseClause)
	c.pos = p.pos()

	switch p.tok {
	case _Case:
		p.next()
		c.Cases = p.exprList()

	case _Default:
		p.next()

	default:
		p.syntaxError("expected case or default or }")
		p.advance(_Colon, _Case, _Default, _Rbrace)
	}

	c.Colon = p.pos()
	p.want(_Colon)
	c.Body = p.stmtList()

	return c
}

func (p *parser) commClause() *CommClause {
	if trace {
		defer p.trace("commClause")()
	}

	c := new(CommClause)
	c.pos = p.pos()

	switch p.tok {
	case _Case:
		p.next()
		c.Comm = p.simpleStmt(nil, 0)

		// The syntax restricts the possible simple statements here to:
		//
		//     lhs <- x (send statement)
		//     <-x
		//     lhs = <-x
		//     lhs := <-x
		//
		// All these (and more) are recognized by simpleStmt and invalid
		// syntax trees are flagged later, during type checking.

	case _Default:
		p.next()

	default:
		p.syntaxError("expected case or default or }")
		p.advance(_Colon, _Case, _Default, _Rbrace)
	}

	c.Colon = p.pos()
	p.want(_Colon)
	c.Body = p.stmtList()

	return c
}

// stmtOrNil parses a statement if one is present, or else returns nil.
//
//	Statement =
//		Declaration | LabeledStmt | SimpleStmt |
//		GoStmt | ReturnStmt | BreakStmt | ContinueStmt | GotoStmt |
//		FallthroughStmt | Block | IfStmt | SwitchStmt | SelectStmt | ForStmt |
//		DeferStmt .
func (p *parser) stmtOrNil() Stmt {
	if trace {
		defer p.trace("stmt " + p.tok.String())()
	}

	// Most statements (assignments) start with an identifier;
	// look for it first before doing anything more expensive.
	if p.tok == _Name {
		p.clearPragma()
		lhs := p.exprList()
		if label, ok := lhs.(*Name); ok && p.tok == _Colon {
			return p.labeledStmtOrNil(label)
		}
		return p.simpleStmt(lhs, 0)
	}

	switch p.tok {
	case _Var:
		return p.declStmt(p.varDecl)

	case _Const:
		return p.declStmt(p.constDecl)

	case _Type:
		return p.declStmt(p.typeDecl)
	}

	p.clearPragma()

	switch p.tok {
	case _Lbrace:
		return p.blockStmt("")

	case _Operator, _Star:
		switch p.op {
		case Add, Sub, Mul, And, Xor, Not:
			return p.simpleStmt(nil, 0) // unary operators
		}

	case _Literal, _Func, _Lparen, // operands
		_Lbrack, _Struct, _Map, _Chan, _Interface, // composite types
		_Arrow: // receive operator
		return p.simpleStmt(nil, 0)

	case _For:
		return p.forStmt()

	case _Switch:
		return p.switchStmt()

	case _Select:
		return p.selectStmt()

	case _If:
		return p.ifStmt()

	case _Fallthrough:
		s := new(BranchStmt)
		s.pos = p.pos()
		p.next()
		s.Tok = _Fallthrough
		return s

	case _Break, _Continue:
		s := new(BranchStmt)
		s.pos = p.pos()
		s.Tok = p.tok
		p.next()
		if p.tok == _Name {
			s.Label = p.name()
		}
		return s

	case _Go, _Defer:
		return p.callStmt()

	case _Goto:
		s := new(BranchStmt)
		s.pos = p.pos()
		s.Tok = _Goto
		p.next()
		s.Label = p.name()
		return s

	case _Return:
		s := new(ReturnStmt)
		s.pos = p.pos()
		p.next()
		if p.tok != _Semi && p.tok != _Rbrace {
			s.Results = p.exprList()
		}
		return s

	case _Semi:
		s := new(EmptyStmt)
		s.pos = p.pos()
		return s
	}

	return nil
}

// StatementList = { Statement ";" } .
func (p *parser) stmtList() (l []Stmt) {
	if trace {
		defer p.trace("stmtList")()
	}

	for p.tok != _EOF && p.tok != _Rbrace && p.tok != _Case && p.tok != _Default {
		s := p.stmtOrNil()
		p.clearPragma()
		if s == nil {
			break
		}
		l = append(l, s)
		// ";" is optional before "}"
		if !p.got(_Semi) && p.tok != _Rbrace {
			p.syntaxError("at end of statement")
			p.advance(_Semi, _Rbrace, _Case, _Default)
			p.got(_Semi) // avoid spurious empty statement
		}
	}
	return
}

// argList parses a possibly empty, comma-separated list of arguments,
// optionally followed by a comma (if not empty), and closed by ")".
// The last argument may be followed by "...".
//
// argList = [ arg { "," arg } [ "..." ] [ "," ] ] ")" .
func (p *parser) argList() (list []Expr, hasDots bool) {
	if trace {
		defer p.trace("argList")()
	}

	p.xnest++
	p.list("argument list", _Comma, _Rparen, func() bool {
		list = append(list, p.expr())
		hasDots = p.got(_DotDotDot)
		return hasDots
	})
	p.xnest--

	return
}

// ----------------------------------------------------------------------------
// Common productions

func (p *parser) name() *Name {
	// no tracing to avoid overly verbose output

	if p.tok == _Name {
		n := NewName(p.pos(), p.lit)
		p.next()
		return n
	}

	n := NewName(p.pos(), "_")
	p.syntaxError("expected name")
	p.advance()
	return n
}

// IdentifierList = identifier { "," identifier } .
// The first name must be provided.
func (p *parser) nameList(first *Name) []*Name {
	if trace {
		defer p.trace("nameList")()
	}

	if debug && first == nil {
		panic("first name not provided")
	}

	l := []*Name{first}
	for p.got(_Comma) {
		l = append(l, p.name())
	}

	return l
}

// The first name may be provided, or nil.
func (p *parser) qualifiedName(name *Name) Expr {
	if trace {
		defer p.trace("qualifiedName")()
	}

	var x Expr
	switch {
	case name != nil:
		x = name
	case p.tok == _Name:
		x = p.name()
	default:
		x = NewName(p.pos(), "_")
		p.syntaxError("expected name")
		p.advance(_Dot, _Semi, _Rbrace)
	}

	if p.tok == _Dot {
		s := new(SelectorExpr)
		s.pos = p.pos()
		p.next()
		s.X = x
		s.Sel = p.name()
		x = s
	}

	if p.tok == _Lbrack {
		x = p.typeInstance(x)
	}

	return x
}

// ExpressionList = Expression { "," Expression } .
func (p *parser) exprList() Expr {
	if trace {
		defer p.trace("exprList")()
	}

	x := p.expr()
	if p.got(_Comma) {
		list := []Expr{x, p.expr()}
		for p.got(_Comma) {
			list = append(list, p.expr())
		}
		t := new(ListExpr)
		t.pos = x.Pos()
		t.ElemList = list
		x = t
	}
	return x
}

// typeList parses a non-empty, comma-separated list of types,
// optionally followed by a comma. If strict is set to false,
// the first element may also be a (non-type) expression.
// If there is more than one argument, the result is a *ListExpr.
// The comma result indicates whether there was a (separating or
// trailing) comma.
//
// typeList = arg { "," arg } [ "," ] .
func (p *parser) typeList(strict bool) (x Expr, comma bool) {
	if trace {
		defer p.trace("typeList")()
	}

	p.xnest++
	if strict {
		x = p.type_()
	} else {
		x = p.expr()
	}
	if p.got(_Comma) {
		comma = true
		if t := p.typeOrNil(); t != nil {
			list := []Expr{x, t}
			for p.got(_Comma) {
				if t = p.typeOrNil(); t == nil {
					break
				}
				list = append(list, t)
			}
			l := new(ListExpr)
			l.pos = x.Pos() // == list[0].Pos()
			l.ElemList = list
			x = l
		}
	}
	p.xnest--
	return
}

// Unparen returns e with any enclosing parentheses stripped.
func Unparen(x Expr) Expr {
	for {
		p, ok := x.(*ParenExpr)
		if !ok {
			break
		}
		x = p.X
	}
	return x
}

// UnpackListExpr unpacks a *ListExpr into a []Expr.
func UnpackListExpr(x Expr) []Expr {
	switch x := x.(type) {
	case nil:
		return nil
	case *ListExpr:
		return x.ElemList
	default:
		return []Expr{x}
	}
}

"""




```