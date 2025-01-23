Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `go/parser` package and specifically resides in the `parser.go` file.

**Plan:**

1. Identify the core functions within the snippet.
2. Determine the purpose of each function.
3. Group related functions to understand broader functionalities.
4. Summarize the overall functionality of the code based on the identified functions.这是 `go/src/go/parser/parser.go` 文件中负责解析 Go 语言类型定义和部分语句定义的部分代码。

**功能归纳：**

这段代码的主要功能是**解析 Go 语言中的各种类型**，包括：

*   **接口类型 (InterfaceType):** 解析 `interface { ... }` 类型的定义。
*   **映射类型 (MapType):** 解析 `map[KeyType]ValueType` 类型的定义。
*   **通道类型 (ChanType):** 解析 `chan ValueType`, `chan<- ValueType`, `<-chan ValueType` 类型的定义。
*   **类型实例 (TypeInstance):** 解析带有类型参数的类型实例，例如 `List[int]`。
*   **各种基本类型表达式:**  通过 `tryIdentOrType` 函数尝试解析标识符、数组、结构体、指针、函数、接口、映射、通道类型以及带括号的类型表达式。
*   **语句块 (BlockStmt):** 解析用 `{}` 包围的代码块。
*   **语句列表 (StmtList):** 解析语句块中的一系列语句。
*   **函数类型或字面量 (FuncTypeOrLit):** 解析函数类型 `func(...) ...` 或函数字面量 `func(...) { ... }`。
*   **操作数 (Operand):** 解析表达式中的基本单元，包括标识符、字面量、带括号的表达式以及函数类型或字面量。
*   **选择器表达式 (SelectorExpr):** 解析结构体字段访问或包名访问，例如 `a.b`。
*   **类型断言表达式 (TypeAssertExpr):** 解析类型断言，例如 `x.(T)`。
*   **索引、切片或类型实例表达式 (parseIndexOrSliceOrInstance):** 解析 `a[index]`, `a[low:high]`, `a[low:high:max]` 或类型实例 `List[int]`。
*   **调用或类型转换表达式 (CallOrConversion):** 解析函数调用 `f()` 或类型转换 `T(x)`。
*   **值 (Value):** 解析字面量值，通常用于复合字面量中。
*   **元素 (Element):** 解析复合字面量中的元素，可以是值或者键值对。
*   **元素列表 (ElementList):** 解析复合字面量中的元素列表。
*   **字面量值 (LiteralValue):** 解析复合字面量，例如 `[]int{1, 2, 3}` 或 `map[string]int{"a": 1}`。
*   **主要表达式 (PrimaryExpr):**  解析表达式的基本构建块，包括操作数以及后续的选择器、索引、调用或复合字面量。
*   **一元表达式 (UnaryExpr):** 解析一元运算符表达式，例如 `!x`, `&y`, `<-ch`。
*   **二元表达式 (BinaryExpr):** 解析二元运算符表达式，例如 `a + b`, `c == d`。
*   **表达式 (Expr):**  作为 `parseBinaryExpr` 的入口，解析各种表达式。
*   **右侧表达式 (Rhs):**  用于区分在赋值语句右侧的表达式解析。
*   **简单语句 (SimpleStmt):** 解析简单的语句，如赋值、发送、自增自减或表达式语句。
*   **Go 语句 (GoStmt):** 解析 `go f()` 语句。
*   **Defer 语句 (DeferStmt):** 解析 `defer f()` 语句。
*   **Return 语句 (ReturnStmt):** 解析 `return` 语句。
*   **分支语句 (BranchStmt):** 解析 `break`, `continue`, `goto`, `fallthrough` 语句。
*   **If 语句 (IfStmt):** 解析 `if` 语句。
*   **Case 子句 (CaseClause):** 解析 `switch` 语句中的 `case` 和 `default` 子句。
*   **Switch 语句 (SwitchStmt):** 解析 `switch` 语句。
*   **Comm 子句 (CommClause):** 解析 `select` 语句中的 `case` 和 `default` 子句。
*   **Select 语句 (SelectStmt):** 解析 `select` 语句。
*   **For 语句 (ForStmt):** 解析 `for` 循环语句，包括 range 循环。
*   **语句 (Stmt):** 作为各种语句解析的入口。
*   **导入声明 (ImportSpec):** 解析 `import` 声明。
*   **值声明 (ValueSpec):** 解析 `const` 和 `var` 声明。
*   **泛型类型 (parseGenericType):** 解析带有类型参数的类型定义。
*   **类型声明 (TypeSpec):** 解析 `type` 声明。

**它可以推理出这是 Go 语言语法解析器的一部分，负责将 Go 源代码文本转换为抽象语法树 (AST)。**

**Go 代码示例说明：**

假设我们有以下 Go 代码片段：

```go
package main

type MyInt int

type List[T any] []T

type MyInterface interface {
    Method1()
    Method2(int) string
}

func main() {
    var a map[string]int
    ch := make(chan int)
    var b List[string]
    var c MyInterface
    _ = a
    _ = ch
    _ = b
    _ = c
}
```

当 `parser.go` 的相关部分解析这段代码时，会生成如下 AST 结构（简化表示）：

*   **`parseMapType()`** 会解析 `map[string]int`，生成一个 `ast.MapType` 节点，其中 `Key` 是 `string` 类型的 `ast.Ident`，`Value` 是 `int` 类型的 `ast.Ident`。
    *   **假设输入:** 当前词法分析器 token 为 `token.MAP`。
    *   **预期输出:**  返回一个指向 `ast.MapType` 结构体的指针，例如：
        ```go
        &ast.MapType{
            Map: /* pos of "map" */,
            Key: &ast.Ident{NamePos: /* pos of "string" */, Name: "string"},
            Value: &ast.Ident{NamePos: /* pos of "int" */, Name: "int"},
        }
        ```
*   **`parseChanType()`** 会解析 `chan int`，生成一个 `ast.ChanType` 节点，`Dir` 为 `ast.SEND | ast.RECV`，`Value` 是 `int` 类型的 `ast.Ident`。
    *   **假设输入:** 当前词法分析器 token 为 `token.CHAN`。
    *   **预期输出:** 返回一个指向 `ast.ChanType` 结构体的指针，例如：
        ```go
        &ast.ChanType{
            Begin: /* pos of "chan" */,
            Dir: ast.SEND | ast.RECV,
            Value: &ast.Ident{NamePos: /* pos of "int" */, Name: "int"},
        }
        ```
*   **`parseTypeInstance()`** 会解析 `List[string]`，生成一个 `ast.IndexListExpr` 或 `ast.IndexExpr` (取决于 Go 版本和泛型实现)。
    *   **假设输入:**  `typ` 是 `List` 的 `ast.Ident`，当前词法分析器 token 为 `token.LBRACK`。
    *   **预期输出:** 返回一个表示类型实例的表达式，例如：
        ```go
        &ast.IndexExpr{
            X: &ast.Ident{NamePos: /* pos of "List" */, Name: "List"},
            Lbrack: /* pos of "[" */,
            Index: &ast.Ident{NamePos: /* pos of "string" */, Name: "string"},
            Rbrack: /* pos of "]" */,
        }
        ```
*   **`parseInterfaceType()`** 会解析 `MyInterface` 的定义，生成一个 `ast.InterfaceType` 节点，其中 `Methods` 包含了 `Method1` 和 `Method2` 的 `ast.Field` 信息。
    *   **假设输入:** 当前词法分析器 token 为 `token.INTERFACE`。
    *   **预期输出:** 返回一个指向 `ast.InterfaceType` 结构体的指针，例如：
        ```go
        &ast.InterfaceType{
            Interface: /* pos of "interface" */,
            Methods: &ast.FieldList{
                Opening: /* pos of "{" */,
                List: []*ast.Field{
                    {Names: []*ast.Ident{{NamePos: /* pos of "Method1" */, Name: "Method1"}}, Type: &ast.FuncType{ /* ... */ }},
                    {Names: []*ast.Ident{{NamePos: /* pos of "Method2" */, Name: "Method2"}}, Type: &ast.FuncType{ /* ... */ }},
                },
                Closing: /* pos of "}" */,
            },
        }
        ```

**使用者易犯错的点：**

这段代码是 Go 语言解析器的内部实现，普通 Go 开发者不会直接使用它。 开发者在使用 `go/parser` 包进行代码分析时，可能会遇到以下容易犯错的点（虽然不是直接与这段代码交互，但理解解析器的工作原理有助于避免这些错误）：

1. **假设解析器能容忍所有语法错误:**  解析器会尽力从错误中恢复，但复杂的语法错误可能导致解析失败或生成不完整的 AST。
2. **不理解 AST 结构:** 修改或分析 AST 之前，需要仔细研究 `go/ast` 包中定义的各种 AST 节点的结构和含义。
3. **忽略错误处理:** `parser.ParseFile` 等函数会返回错误，必须正确处理这些错误，否则可能会基于错误的 AST 进行后续操作。

总而言之，这段代码是 Go 语言解析器中至关重要的一部分，它负责将 Go 源代码中的类型定义和部分语句转换为计算机可以理解的抽象语法树，为后续的类型检查、代码生成等步骤奠定基础。

### 提示词
```
这是路径为go/src/go/parser/parser.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```go
'type', or a '}' at this point.
	rbrace := p.expect(token.RBRACE)

	return &ast.InterfaceType{
		Interface: pos,
		Methods: &ast.FieldList{
			Opening: lbrace,
			List:    list,
			Closing: rbrace,
		},
	}
}

func (p *parser) parseMapType() *ast.MapType {
	if p.trace {
		defer un(trace(p, "MapType"))
	}

	pos := p.expect(token.MAP)
	p.expect(token.LBRACK)
	key := p.parseType()
	p.expect(token.RBRACK)
	value := p.parseType()

	return &ast.MapType{Map: pos, Key: key, Value: value}
}

func (p *parser) parseChanType() *ast.ChanType {
	if p.trace {
		defer un(trace(p, "ChanType"))
	}

	pos := p.pos
	dir := ast.SEND | ast.RECV
	var arrow token.Pos
	if p.tok == token.CHAN {
		p.next()
		if p.tok == token.ARROW {
			arrow = p.pos
			p.next()
			dir = ast.SEND
		}
	} else {
		arrow = p.expect(token.ARROW)
		p.expect(token.CHAN)
		dir = ast.RECV
	}
	value := p.parseType()

	return &ast.ChanType{Begin: pos, Arrow: arrow, Dir: dir, Value: value}
}

func (p *parser) parseTypeInstance(typ ast.Expr) ast.Expr {
	if p.trace {
		defer un(trace(p, "TypeInstance"))
	}

	opening := p.expect(token.LBRACK)
	p.exprLev++
	var list []ast.Expr
	for p.tok != token.RBRACK && p.tok != token.EOF {
		list = append(list, p.parseType())
		if !p.atComma("type argument list", token.RBRACK) {
			break
		}
		p.next()
	}
	p.exprLev--

	closing := p.expectClosing(token.RBRACK, "type argument list")

	if len(list) == 0 {
		p.errorExpected(closing, "type argument list")
		return &ast.IndexExpr{
			X:      typ,
			Lbrack: opening,
			Index:  &ast.BadExpr{From: opening + 1, To: closing},
			Rbrack: closing,
		}
	}

	return packIndexExpr(typ, opening, list, closing)
}

func (p *parser) tryIdentOrType() ast.Expr {
	defer decNestLev(incNestLev(p))

	switch p.tok {
	case token.IDENT:
		typ := p.parseTypeName(nil)
		if p.tok == token.LBRACK {
			typ = p.parseTypeInstance(typ)
		}
		return typ
	case token.LBRACK:
		lbrack := p.expect(token.LBRACK)
		return p.parseArrayType(lbrack, nil)
	case token.STRUCT:
		return p.parseStructType()
	case token.MUL:
		return p.parsePointerType()
	case token.FUNC:
		return p.parseFuncType()
	case token.INTERFACE:
		return p.parseInterfaceType()
	case token.MAP:
		return p.parseMapType()
	case token.CHAN, token.ARROW:
		return p.parseChanType()
	case token.LPAREN:
		lparen := p.pos
		p.next()
		typ := p.parseType()
		rparen := p.expect(token.RPAREN)
		return &ast.ParenExpr{Lparen: lparen, X: typ, Rparen: rparen}
	}

	// no type found
	return nil
}

// ----------------------------------------------------------------------------
// Blocks

func (p *parser) parseStmtList() (list []ast.Stmt) {
	if p.trace {
		defer un(trace(p, "StatementList"))
	}

	for p.tok != token.CASE && p.tok != token.DEFAULT && p.tok != token.RBRACE && p.tok != token.EOF {
		list = append(list, p.parseStmt())
	}

	return
}

func (p *parser) parseBody() *ast.BlockStmt {
	if p.trace {
		defer un(trace(p, "Body"))
	}

	lbrace := p.expect(token.LBRACE)
	list := p.parseStmtList()
	rbrace := p.expect2(token.RBRACE)

	return &ast.BlockStmt{Lbrace: lbrace, List: list, Rbrace: rbrace}
}

func (p *parser) parseBlockStmt() *ast.BlockStmt {
	if p.trace {
		defer un(trace(p, "BlockStmt"))
	}

	lbrace := p.expect(token.LBRACE)
	list := p.parseStmtList()
	rbrace := p.expect2(token.RBRACE)

	return &ast.BlockStmt{Lbrace: lbrace, List: list, Rbrace: rbrace}
}

// ----------------------------------------------------------------------------
// Expressions

func (p *parser) parseFuncTypeOrLit() ast.Expr {
	if p.trace {
		defer un(trace(p, "FuncTypeOrLit"))
	}

	typ := p.parseFuncType()
	if p.tok != token.LBRACE {
		// function type only
		return typ
	}

	p.exprLev++
	body := p.parseBody()
	p.exprLev--

	return &ast.FuncLit{Type: typ, Body: body}
}

// parseOperand may return an expression or a raw type (incl. array
// types of the form [...]T). Callers must verify the result.
func (p *parser) parseOperand() ast.Expr {
	if p.trace {
		defer un(trace(p, "Operand"))
	}

	switch p.tok {
	case token.IDENT:
		x := p.parseIdent()
		return x

	case token.INT, token.FLOAT, token.IMAG, token.CHAR, token.STRING:
		x := &ast.BasicLit{ValuePos: p.pos, Kind: p.tok, Value: p.lit}
		p.next()
		return x

	case token.LPAREN:
		lparen := p.pos
		p.next()
		p.exprLev++
		x := p.parseRhs() // types may be parenthesized: (some type)
		p.exprLev--
		rparen := p.expect(token.RPAREN)
		return &ast.ParenExpr{Lparen: lparen, X: x, Rparen: rparen}

	case token.FUNC:
		return p.parseFuncTypeOrLit()
	}

	if typ := p.tryIdentOrType(); typ != nil { // do not consume trailing type parameters
		// could be type for composite literal or conversion
		_, isIdent := typ.(*ast.Ident)
		assert(!isIdent, "type cannot be identifier")
		return typ
	}

	// we have an error
	pos := p.pos
	p.errorExpected(pos, "operand")
	p.advance(stmtStart)
	return &ast.BadExpr{From: pos, To: p.pos}
}

func (p *parser) parseSelector(x ast.Expr) ast.Expr {
	if p.trace {
		defer un(trace(p, "Selector"))
	}

	sel := p.parseIdent()

	return &ast.SelectorExpr{X: x, Sel: sel}
}

func (p *parser) parseTypeAssertion(x ast.Expr) ast.Expr {
	if p.trace {
		defer un(trace(p, "TypeAssertion"))
	}

	lparen := p.expect(token.LPAREN)
	var typ ast.Expr
	if p.tok == token.TYPE {
		// type switch: typ == nil
		p.next()
	} else {
		typ = p.parseType()
	}
	rparen := p.expect(token.RPAREN)

	return &ast.TypeAssertExpr{X: x, Type: typ, Lparen: lparen, Rparen: rparen}
}

func (p *parser) parseIndexOrSliceOrInstance(x ast.Expr) ast.Expr {
	if p.trace {
		defer un(trace(p, "parseIndexOrSliceOrInstance"))
	}

	lbrack := p.expect(token.LBRACK)
	if p.tok == token.RBRACK {
		// empty index, slice or index expressions are not permitted;
		// accept them for parsing tolerance, but complain
		p.errorExpected(p.pos, "operand")
		rbrack := p.pos
		p.next()
		return &ast.IndexExpr{
			X:      x,
			Lbrack: lbrack,
			Index:  &ast.BadExpr{From: rbrack, To: rbrack},
			Rbrack: rbrack,
		}
	}
	p.exprLev++

	const N = 3 // change the 3 to 2 to disable 3-index slices
	var args []ast.Expr
	var index [N]ast.Expr
	var colons [N - 1]token.Pos
	if p.tok != token.COLON {
		// We can't know if we have an index expression or a type instantiation;
		// so even if we see a (named) type we are not going to be in type context.
		index[0] = p.parseRhs()
	}
	ncolons := 0
	switch p.tok {
	case token.COLON:
		// slice expression
		for p.tok == token.COLON && ncolons < len(colons) {
			colons[ncolons] = p.pos
			ncolons++
			p.next()
			if p.tok != token.COLON && p.tok != token.RBRACK && p.tok != token.EOF {
				index[ncolons] = p.parseRhs()
			}
		}
	case token.COMMA:
		// instance expression
		args = append(args, index[0])
		for p.tok == token.COMMA {
			p.next()
			if p.tok != token.RBRACK && p.tok != token.EOF {
				args = append(args, p.parseType())
			}
		}
	}

	p.exprLev--
	rbrack := p.expect(token.RBRACK)

	if ncolons > 0 {
		// slice expression
		slice3 := false
		if ncolons == 2 {
			slice3 = true
			// Check presence of middle and final index here rather than during type-checking
			// to prevent erroneous programs from passing through gofmt (was go.dev/issue/7305).
			if index[1] == nil {
				p.error(colons[0], "middle index required in 3-index slice")
				index[1] = &ast.BadExpr{From: colons[0] + 1, To: colons[1]}
			}
			if index[2] == nil {
				p.error(colons[1], "final index required in 3-index slice")
				index[2] = &ast.BadExpr{From: colons[1] + 1, To: rbrack}
			}
		}
		return &ast.SliceExpr{X: x, Lbrack: lbrack, Low: index[0], High: index[1], Max: index[2], Slice3: slice3, Rbrack: rbrack}
	}

	if len(args) == 0 {
		// index expression
		return &ast.IndexExpr{X: x, Lbrack: lbrack, Index: index[0], Rbrack: rbrack}
	}

	// instance expression
	return packIndexExpr(x, lbrack, args, rbrack)
}

func (p *parser) parseCallOrConversion(fun ast.Expr) *ast.CallExpr {
	if p.trace {
		defer un(trace(p, "CallOrConversion"))
	}

	lparen := p.expect(token.LPAREN)
	p.exprLev++
	var list []ast.Expr
	var ellipsis token.Pos
	for p.tok != token.RPAREN && p.tok != token.EOF && !ellipsis.IsValid() {
		list = append(list, p.parseRhs()) // builtins may expect a type: make(some type, ...)
		if p.tok == token.ELLIPSIS {
			ellipsis = p.pos
			p.next()
		}
		if !p.atComma("argument list", token.RPAREN) {
			break
		}
		p.next()
	}
	p.exprLev--
	rparen := p.expectClosing(token.RPAREN, "argument list")

	return &ast.CallExpr{Fun: fun, Lparen: lparen, Args: list, Ellipsis: ellipsis, Rparen: rparen}
}

func (p *parser) parseValue() ast.Expr {
	if p.trace {
		defer un(trace(p, "Element"))
	}

	if p.tok == token.LBRACE {
		return p.parseLiteralValue(nil)
	}

	x := p.parseExpr()

	return x
}

func (p *parser) parseElement() ast.Expr {
	if p.trace {
		defer un(trace(p, "Element"))
	}

	x := p.parseValue()
	if p.tok == token.COLON {
		colon := p.pos
		p.next()
		x = &ast.KeyValueExpr{Key: x, Colon: colon, Value: p.parseValue()}
	}

	return x
}

func (p *parser) parseElementList() (list []ast.Expr) {
	if p.trace {
		defer un(trace(p, "ElementList"))
	}

	for p.tok != token.RBRACE && p.tok != token.EOF {
		list = append(list, p.parseElement())
		if !p.atComma("composite literal", token.RBRACE) {
			break
		}
		p.next()
	}

	return
}

func (p *parser) parseLiteralValue(typ ast.Expr) ast.Expr {
	defer decNestLev(incNestLev(p))

	if p.trace {
		defer un(trace(p, "LiteralValue"))
	}

	lbrace := p.expect(token.LBRACE)
	var elts []ast.Expr
	p.exprLev++
	if p.tok != token.RBRACE {
		elts = p.parseElementList()
	}
	p.exprLev--
	rbrace := p.expectClosing(token.RBRACE, "composite literal")
	return &ast.CompositeLit{Type: typ, Lbrace: lbrace, Elts: elts, Rbrace: rbrace}
}

func (p *parser) parsePrimaryExpr(x ast.Expr) ast.Expr {
	if p.trace {
		defer un(trace(p, "PrimaryExpr"))
	}

	if x == nil {
		x = p.parseOperand()
	}
	// We track the nesting here rather than at the entry for the function,
	// since it can iteratively produce a nested output, and we want to
	// limit how deep a structure we generate.
	var n int
	defer func() { p.nestLev -= n }()
	for n = 1; ; n++ {
		incNestLev(p)
		switch p.tok {
		case token.PERIOD:
			p.next()
			switch p.tok {
			case token.IDENT:
				x = p.parseSelector(x)
			case token.LPAREN:
				x = p.parseTypeAssertion(x)
			default:
				pos := p.pos
				p.errorExpected(pos, "selector or type assertion")
				// TODO(rFindley) The check for token.RBRACE below is a targeted fix
				//                to error recovery sufficient to make the x/tools tests to
				//                pass with the new parsing logic introduced for type
				//                parameters. Remove this once error recovery has been
				//                more generally reconsidered.
				if p.tok != token.RBRACE {
					p.next() // make progress
				}
				sel := &ast.Ident{NamePos: pos, Name: "_"}
				x = &ast.SelectorExpr{X: x, Sel: sel}
			}
		case token.LBRACK:
			x = p.parseIndexOrSliceOrInstance(x)
		case token.LPAREN:
			x = p.parseCallOrConversion(x)
		case token.LBRACE:
			// operand may have returned a parenthesized complit
			// type; accept it but complain if we have a complit
			t := ast.Unparen(x)
			// determine if '{' belongs to a composite literal or a block statement
			switch t.(type) {
			case *ast.BadExpr, *ast.Ident, *ast.SelectorExpr:
				if p.exprLev < 0 {
					return x
				}
				// x is possibly a composite literal type
			case *ast.IndexExpr, *ast.IndexListExpr:
				if p.exprLev < 0 {
					return x
				}
				// x is possibly a composite literal type
			case *ast.ArrayType, *ast.StructType, *ast.MapType:
				// x is a composite literal type
			default:
				return x
			}
			if t != x {
				p.error(t.Pos(), "cannot parenthesize type in composite literal")
				// already progressed, no need to advance
			}
			x = p.parseLiteralValue(x)
		default:
			return x
		}
	}
}

func (p *parser) parseUnaryExpr() ast.Expr {
	defer decNestLev(incNestLev(p))

	if p.trace {
		defer un(trace(p, "UnaryExpr"))
	}

	switch p.tok {
	case token.ADD, token.SUB, token.NOT, token.XOR, token.AND, token.TILDE:
		pos, op := p.pos, p.tok
		p.next()
		x := p.parseUnaryExpr()
		return &ast.UnaryExpr{OpPos: pos, Op: op, X: x}

	case token.ARROW:
		// channel type or receive expression
		arrow := p.pos
		p.next()

		// If the next token is token.CHAN we still don't know if it
		// is a channel type or a receive operation - we only know
		// once we have found the end of the unary expression. There
		// are two cases:
		//
		//   <- type  => (<-type) must be channel type
		//   <- expr  => <-(expr) is a receive from an expression
		//
		// In the first case, the arrow must be re-associated with
		// the channel type parsed already:
		//
		//   <- (chan type)    =>  (<-chan type)
		//   <- (chan<- type)  =>  (<-chan (<-type))

		x := p.parseUnaryExpr()

		// determine which case we have
		if typ, ok := x.(*ast.ChanType); ok {
			// (<-type)

			// re-associate position info and <-
			dir := ast.SEND
			for ok && dir == ast.SEND {
				if typ.Dir == ast.RECV {
					// error: (<-type) is (<-(<-chan T))
					p.errorExpected(typ.Arrow, "'chan'")
				}
				arrow, typ.Begin, typ.Arrow = typ.Arrow, arrow, arrow
				dir, typ.Dir = typ.Dir, ast.RECV
				typ, ok = typ.Value.(*ast.ChanType)
			}
			if dir == ast.SEND {
				p.errorExpected(arrow, "channel type")
			}

			return x
		}

		// <-(expr)
		return &ast.UnaryExpr{OpPos: arrow, Op: token.ARROW, X: x}

	case token.MUL:
		// pointer type or unary "*" expression
		pos := p.pos
		p.next()
		x := p.parseUnaryExpr()
		return &ast.StarExpr{Star: pos, X: x}
	}

	return p.parsePrimaryExpr(nil)
}

func (p *parser) tokPrec() (token.Token, int) {
	tok := p.tok
	if p.inRhs && tok == token.ASSIGN {
		tok = token.EQL
	}
	return tok, tok.Precedence()
}

// parseBinaryExpr parses a (possibly) binary expression.
// If x is non-nil, it is used as the left operand.
//
// TODO(rfindley): parseBinaryExpr has become overloaded. Consider refactoring.
func (p *parser) parseBinaryExpr(x ast.Expr, prec1 int) ast.Expr {
	if p.trace {
		defer un(trace(p, "BinaryExpr"))
	}

	if x == nil {
		x = p.parseUnaryExpr()
	}
	// We track the nesting here rather than at the entry for the function,
	// since it can iteratively produce a nested output, and we want to
	// limit how deep a structure we generate.
	var n int
	defer func() { p.nestLev -= n }()
	for n = 1; ; n++ {
		incNestLev(p)
		op, oprec := p.tokPrec()
		if oprec < prec1 {
			return x
		}
		pos := p.expect(op)
		y := p.parseBinaryExpr(nil, oprec+1)
		x = &ast.BinaryExpr{X: x, OpPos: pos, Op: op, Y: y}
	}
}

// The result may be a type or even a raw type ([...]int).
func (p *parser) parseExpr() ast.Expr {
	if p.trace {
		defer un(trace(p, "Expression"))
	}

	return p.parseBinaryExpr(nil, token.LowestPrec+1)
}

func (p *parser) parseRhs() ast.Expr {
	old := p.inRhs
	p.inRhs = true
	x := p.parseExpr()
	p.inRhs = old
	return x
}

// ----------------------------------------------------------------------------
// Statements

// Parsing modes for parseSimpleStmt.
const (
	basic = iota
	labelOk
	rangeOk
)

// parseSimpleStmt returns true as 2nd result if it parsed the assignment
// of a range clause (with mode == rangeOk). The returned statement is an
// assignment with a right-hand side that is a single unary expression of
// the form "range x". No guarantees are given for the left-hand side.
func (p *parser) parseSimpleStmt(mode int) (ast.Stmt, bool) {
	if p.trace {
		defer un(trace(p, "SimpleStmt"))
	}

	x := p.parseList(false)

	switch p.tok {
	case
		token.DEFINE, token.ASSIGN, token.ADD_ASSIGN,
		token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN,
		token.REM_ASSIGN, token.AND_ASSIGN, token.OR_ASSIGN,
		token.XOR_ASSIGN, token.SHL_ASSIGN, token.SHR_ASSIGN, token.AND_NOT_ASSIGN:
		// assignment statement, possibly part of a range clause
		pos, tok := p.pos, p.tok
		p.next()
		var y []ast.Expr
		isRange := false
		if mode == rangeOk && p.tok == token.RANGE && (tok == token.DEFINE || tok == token.ASSIGN) {
			pos := p.pos
			p.next()
			y = []ast.Expr{&ast.UnaryExpr{OpPos: pos, Op: token.RANGE, X: p.parseRhs()}}
			isRange = true
		} else {
			y = p.parseList(true)
		}
		return &ast.AssignStmt{Lhs: x, TokPos: pos, Tok: tok, Rhs: y}, isRange
	}

	if len(x) > 1 {
		p.errorExpected(x[0].Pos(), "1 expression")
		// continue with first expression
	}

	switch p.tok {
	case token.COLON:
		// labeled statement
		colon := p.pos
		p.next()
		if label, isIdent := x[0].(*ast.Ident); mode == labelOk && isIdent {
			// Go spec: The scope of a label is the body of the function
			// in which it is declared and excludes the body of any nested
			// function.
			stmt := &ast.LabeledStmt{Label: label, Colon: colon, Stmt: p.parseStmt()}
			return stmt, false
		}
		// The label declaration typically starts at x[0].Pos(), but the label
		// declaration may be erroneous due to a token after that position (and
		// before the ':'). If SpuriousErrors is not set, the (only) error
		// reported for the line is the illegal label error instead of the token
		// before the ':' that caused the problem. Thus, use the (latest) colon
		// position for error reporting.
		p.error(colon, "illegal label declaration")
		return &ast.BadStmt{From: x[0].Pos(), To: colon + 1}, false

	case token.ARROW:
		// send statement
		arrow := p.pos
		p.next()
		y := p.parseRhs()
		return &ast.SendStmt{Chan: x[0], Arrow: arrow, Value: y}, false

	case token.INC, token.DEC:
		// increment or decrement
		s := &ast.IncDecStmt{X: x[0], TokPos: p.pos, Tok: p.tok}
		p.next()
		return s, false
	}

	// expression
	return &ast.ExprStmt{X: x[0]}, false
}

func (p *parser) parseCallExpr(callType string) *ast.CallExpr {
	x := p.parseRhs() // could be a conversion: (some type)(x)
	if t := ast.Unparen(x); t != x {
		p.error(x.Pos(), fmt.Sprintf("expression in %s must not be parenthesized", callType))
		x = t
	}
	if call, isCall := x.(*ast.CallExpr); isCall {
		return call
	}
	if _, isBad := x.(*ast.BadExpr); !isBad {
		// only report error if it's a new one
		p.error(p.safePos(x.End()), fmt.Sprintf("expression in %s must be function call", callType))
	}
	return nil
}

func (p *parser) parseGoStmt() ast.Stmt {
	if p.trace {
		defer un(trace(p, "GoStmt"))
	}

	pos := p.expect(token.GO)
	call := p.parseCallExpr("go")
	p.expectSemi()
	if call == nil {
		return &ast.BadStmt{From: pos, To: pos + 2} // len("go")
	}

	return &ast.GoStmt{Go: pos, Call: call}
}

func (p *parser) parseDeferStmt() ast.Stmt {
	if p.trace {
		defer un(trace(p, "DeferStmt"))
	}

	pos := p.expect(token.DEFER)
	call := p.parseCallExpr("defer")
	p.expectSemi()
	if call == nil {
		return &ast.BadStmt{From: pos, To: pos + 5} // len("defer")
	}

	return &ast.DeferStmt{Defer: pos, Call: call}
}

func (p *parser) parseReturnStmt() *ast.ReturnStmt {
	if p.trace {
		defer un(trace(p, "ReturnStmt"))
	}

	pos := p.pos
	p.expect(token.RETURN)
	var x []ast.Expr
	if p.tok != token.SEMICOLON && p.tok != token.RBRACE {
		x = p.parseList(true)
	}
	p.expectSemi()

	return &ast.ReturnStmt{Return: pos, Results: x}
}

func (p *parser) parseBranchStmt(tok token.Token) *ast.BranchStmt {
	if p.trace {
		defer un(trace(p, "BranchStmt"))
	}

	pos := p.expect(tok)
	var label *ast.Ident
	if tok != token.FALLTHROUGH && p.tok == token.IDENT {
		label = p.parseIdent()
	}
	p.expectSemi()

	return &ast.BranchStmt{TokPos: pos, Tok: tok, Label: label}
}

func (p *parser) makeExpr(s ast.Stmt, want string) ast.Expr {
	if s == nil {
		return nil
	}
	if es, isExpr := s.(*ast.ExprStmt); isExpr {
		return es.X
	}
	found := "simple statement"
	if _, isAss := s.(*ast.AssignStmt); isAss {
		found = "assignment"
	}
	p.error(s.Pos(), fmt.Sprintf("expected %s, found %s (missing parentheses around composite literal?)", want, found))
	return &ast.BadExpr{From: s.Pos(), To: p.safePos(s.End())}
}

// parseIfHeader is an adjusted version of parser.header
// in cmd/compile/internal/syntax/parser.go, which has
// been tuned for better error handling.
func (p *parser) parseIfHeader() (init ast.Stmt, cond ast.Expr) {
	if p.tok == token.LBRACE {
		p.error(p.pos, "missing condition in if statement")
		cond = &ast.BadExpr{From: p.pos, To: p.pos}
		return
	}
	// p.tok != token.LBRACE

	prevLev := p.exprLev
	p.exprLev = -1

	if p.tok != token.SEMICOLON {
		// accept potential variable declaration but complain
		if p.tok == token.VAR {
			p.next()
			p.error(p.pos, "var declaration not allowed in if initializer")
		}
		init, _ = p.parseSimpleStmt(basic)
	}

	var condStmt ast.Stmt
	var semi struct {
		pos token.Pos
		lit string // ";" or "\n"; valid if pos.IsValid()
	}
	if p.tok != token.LBRACE {
		if p.tok == token.SEMICOLON {
			semi.pos = p.pos
			semi.lit = p.lit
			p.next()
		} else {
			p.expect(token.SEMICOLON)
		}
		if p.tok != token.LBRACE {
			condStmt, _ = p.parseSimpleStmt(basic)
		}
	} else {
		condStmt = init
		init = nil
	}

	if condStmt != nil {
		cond = p.makeExpr(condStmt, "boolean expression")
	} else if semi.pos.IsValid() {
		if semi.lit == "\n" {
			p.error(semi.pos, "unexpected newline, expecting { after if clause")
		} else {
			p.error(semi.pos, "missing condition in if statement")
		}
	}

	// make sure we have a valid AST
	if cond == nil {
		cond = &ast.BadExpr{From: p.pos, To: p.pos}
	}

	p.exprLev = prevLev
	return
}

func (p *parser) parseIfStmt() *ast.IfStmt {
	defer decNestLev(incNestLev(p))

	if p.trace {
		defer un(trace(p, "IfStmt"))
	}

	pos := p.expect(token.IF)

	init, cond := p.parseIfHeader()
	body := p.parseBlockStmt()

	var else_ ast.Stmt
	if p.tok == token.ELSE {
		p.next()
		switch p.tok {
		case token.IF:
			else_ = p.parseIfStmt()
		case token.LBRACE:
			else_ = p.parseBlockStmt()
			p.expectSemi()
		default:
			p.errorExpected(p.pos, "if statement or block")
			else_ = &ast.BadStmt{From: p.pos, To: p.pos}
		}
	} else {
		p.expectSemi()
	}

	return &ast.IfStmt{If: pos, Init: init, Cond: cond, Body: body, Else: else_}
}

func (p *parser) parseCaseClause() *ast.CaseClause {
	if p.trace {
		defer un(trace(p, "CaseClause"))
	}

	pos := p.pos
	var list []ast.Expr
	if p.tok == token.CASE {
		p.next()
		list = p.parseList(true)
	} else {
		p.expect(token.DEFAULT)
	}

	colon := p.expect(token.COLON)
	body := p.parseStmtList()

	return &ast.CaseClause{Case: pos, List: list, Colon: colon, Body: body}
}

func isTypeSwitchAssert(x ast.Expr) bool {
	a, ok := x.(*ast.TypeAssertExpr)
	return ok && a.Type == nil
}

func (p *parser) isTypeSwitchGuard(s ast.Stmt) bool {
	switch t := s.(type) {
	case *ast.ExprStmt:
		// x.(type)
		return isTypeSwitchAssert(t.X)
	case *ast.AssignStmt:
		// v := x.(type)
		if len(t.Lhs) == 1 && len(t.Rhs) == 1 && isTypeSwitchAssert(t.Rhs[0]) {
			switch t.Tok {
			case token.ASSIGN:
				// permit v = x.(type) but complain
				p.error(t.TokPos, "expected ':=', found '='")
				fallthrough
			case token.DEFINE:
				return true
			}
		}
	}
	return false
}

func (p *parser) parseSwitchStmt() ast.Stmt {
	if p.trace {
		defer un(trace(p, "SwitchStmt"))
	}

	pos := p.expect(token.SWITCH)

	var s1, s2 ast.Stmt
	if p.tok != token.LBRACE {
		prevLev := p.exprLev
		p.exprLev = -1
		if p.tok != token.SEMICOLON {
			s2, _ = p.parseSimpleStmt(basic)
		}
		if p.tok == token.SEMICOLON {
			p.next()
			s1 = s2
			s2 = nil
			if p.tok != token.LBRACE {
				// A TypeSwitchGuard may declare a variable in addition
				// to the variable declared in the initial SimpleStmt.
				// Introduce extra scope to avoid redeclaration errors:
				//
				//	switch t := 0; t := x.(T) { ... }
				//
				// (this code is not valid Go because the first t
				// cannot be accessed and thus is never used, the extra
				// scope is needed for the correct error message).
				//
				// If we don't have a type switch, s2 must be an expression.
				// Having the extra nested but empty scope won't affect it.
				s2, _ = p.parseSimpleStmt(basic)
			}
		}
		p.exprLev = prevLev
	}

	typeSwitch := p.isTypeSwitchGuard(s2)
	lbrace := p.expect(token.LBRACE)
	var list []ast.Stmt
	for p.tok == token.CASE || p.tok == token.DEFAULT {
		list = append(list, p.parseCaseClause())
	}
	rbrace := p.expect(token.RBRACE)
	p.expectSemi()
	body := &ast.BlockStmt{Lbrace: lbrace, List: list, Rbrace: rbrace}

	if typeSwitch {
		return &ast.TypeSwitchStmt{Switch: pos, Init: s1, Assign: s2, Body: body}
	}

	return &ast.SwitchStmt{Switch: pos, Init: s1, Tag: p.makeExpr(s2, "switch expression"), Body: body}
}

func (p *parser) parseCommClause() *ast.CommClause {
	if p.trace {
		defer un(trace(p, "CommClause"))
	}

	pos := p.pos
	var comm ast.Stmt
	if p.tok == token.CASE {
		p.next()
		lhs := p.parseList(false)
		if p.tok == token.ARROW {
			// SendStmt
			if len(lhs) > 1 {
				p.errorExpected(lhs[0].Pos(), "1 expression")
				// continue with first expression
			}
			arrow := p.pos
			p.next()
			rhs := p.parseRhs()
			comm = &ast.SendStmt{Chan: lhs[0], Arrow: arrow, Value: rhs}
		} else {
			// RecvStmt
			if tok := p.tok; tok == token.ASSIGN || tok == token.DEFINE {
				// RecvStmt with assignment
				if len(lhs) > 2 {
					p.errorExpected(lhs[0].Pos(), "1 or 2 expressions")
					// continue with first two expressions
					lhs = lhs[0:2]
				}
				pos := p.pos
				p.next()
				rhs := p.parseRhs()
				comm = &ast.AssignStmt{Lhs: lhs, TokPos: pos, Tok: tok, Rhs: []ast.Expr{rhs}}
			} else {
				// lhs must be single receive operation
				if len(lhs) > 1 {
					p.errorExpected(lhs[0].Pos(), "1 expression")
					// continue with first expression
				}
				comm = &ast.ExprStmt{X: lhs[0]}
			}
		}
	} else {
		p.expect(token.DEFAULT)
	}

	colon := p.expect(token.COLON)
	body := p.parseStmtList()

	return &ast.CommClause{Case: pos, Comm: comm, Colon: colon, Body: body}
}

func (p *parser) parseSelectStmt() *ast.SelectStmt {
	if p.trace {
		defer un(trace(p, "SelectStmt"))
	}

	pos := p.expect(token.SELECT)
	lbrace := p.expect(token.LBRACE)
	var list []ast.Stmt
	for p.tok == token.CASE || p.tok == token.DEFAULT {
		list = append(list, p.parseCommClause())
	}
	rbrace := p.expect(token.RBRACE)
	p.expectSemi()
	body := &ast.BlockStmt{Lbrace: lbrace, List: list, Rbrace: rbrace}

	return &ast.SelectStmt{Select: pos, Body: body}
}

func (p *parser) parseForStmt() ast.Stmt {
	if p.trace {
		defer un(trace(p, "ForStmt"))
	}

	pos := p.expect(token.FOR)

	var s1, s2, s3 ast.Stmt
	var isRange bool
	if p.tok != token.LBRACE {
		prevLev := p.exprLev
		p.exprLev = -1
		if p.tok != token.SEMICOLON {
			if p.tok == token.RANGE {
				// "for range x" (nil lhs in assignment)
				pos := p.pos
				p.next()
				y := []ast.Expr{&ast.UnaryExpr{OpPos: pos, Op: token.RANGE, X: p.parseRhs()}}
				s2 = &ast.AssignStmt{Rhs: y}
				isRange = true
			} else {
				s2, isRange = p.parseSimpleStmt(rangeOk)
			}
		}
		if !isRange && p.tok == token.SEMICOLON {
			p.next()
			s1 = s2
			s2 = nil
			if p.tok != token.SEMICOLON {
				s2, _ = p.parseSimpleStmt(basic)
			}
			p.expectSemi()
			if p.tok != token.LBRACE {
				s3, _ = p.parseSimpleStmt(basic)
			}
		}
		p.exprLev = prevLev
	}

	body := p.parseBlockStmt()
	p.expectSemi()

	if isRange {
		as := s2.(*ast.AssignStmt)
		// check lhs
		var key, value ast.Expr
		switch len(as.Lhs) {
		case 0:
			// nothing to do
		case 1:
			key = as.Lhs[0]
		case 2:
			key, value = as.Lhs[0], as.Lhs[1]
		default:
			p.errorExpected(as.Lhs[len(as.Lhs)-1].Pos(), "at most 2 expressions")
			return &ast.BadStmt{From: pos, To: p.safePos(body.End())}
		}
		// parseSimpleStmt returned a right-hand side that
		// is a single unary expression of the form "range x"
		x := as.Rhs[0].(*ast.UnaryExpr).X
		return &ast.RangeStmt{
			For:    pos,
			Key:    key,
			Value:  value,
			TokPos: as.TokPos,
			Tok:    as.Tok,
			Range:  as.Rhs[0].Pos(),
			X:      x,
			Body:   body,
		}
	}

	// regular for statement
	return &ast.ForStmt{
		For:  pos,
		Init: s1,
		Cond: p.makeExpr(s2, "boolean or range expression"),
		Post: s3,
		Body: body,
	}
}

func (p *parser) parseStmt() (s ast.Stmt) {
	defer decNestLev(incNestLev(p))

	if p.trace {
		defer un(trace(p, "Statement"))
	}

	switch p.tok {
	case token.CONST, token.TYPE, token.VAR:
		s = &ast.DeclStmt{Decl: p.parseDecl(stmtStart)}
	case
		// tokens that may start an expression
		token.IDENT, token.INT, token.FLOAT, token.IMAG, token.CHAR, token.STRING, token.FUNC, token.LPAREN, // operands
		token.LBRACK, token.STRUCT, token.MAP, token.CHAN, token.INTERFACE, // composite types
		token.ADD, token.SUB, token.MUL, token.AND, token.XOR, token.ARROW, token.NOT: // unary operators
		s, _ = p.parseSimpleStmt(labelOk)
		// because of the required look-ahead, labeled statements are
		// parsed by parseSimpleStmt - don't expect a semicolon after
		// them
		if _, isLabeledStmt := s.(*ast.LabeledStmt); !isLabeledStmt {
			p.expectSemi()
		}
	case token.GO:
		s = p.parseGoStmt()
	case token.DEFER:
		s = p.parseDeferStmt()
	case token.RETURN:
		s = p.parseReturnStmt()
	case token.BREAK, token.CONTINUE, token.GOTO, token.FALLTHROUGH:
		s = p.parseBranchStmt(p.tok)
	case token.LBRACE:
		s = p.parseBlockStmt()
		p.expectSemi()
	case token.IF:
		s = p.parseIfStmt()
	case token.SWITCH:
		s = p.parseSwitchStmt()
	case token.SELECT:
		s = p.parseSelectStmt()
	case token.FOR:
		s = p.parseForStmt()
	case token.SEMICOLON:
		// Is it ever possible to have an implicit semicolon
		// producing an empty statement in a valid program?
		// (handle correctly anyway)
		s = &ast.EmptyStmt{Semicolon: p.pos, Implicit: p.lit == "\n"}
		p.next()
	case token.RBRACE:
		// a semicolon may be omitted before a closing "}"
		s = &ast.EmptyStmt{Semicolon: p.pos, Implicit: true}
	default:
		// no statement found
		pos := p.pos
		p.errorExpected(pos, "statement")
		p.advance(stmtStart)
		s = &ast.BadStmt{From: pos, To: p.pos}
	}

	return
}

// ----------------------------------------------------------------------------
// Declarations

type parseSpecFunction func(doc *ast.CommentGroup, keyword token.Token, iota int) ast.Spec

func (p *parser) parseImportSpec(doc *ast.CommentGroup, _ token.Token, _ int) ast.Spec {
	if p.trace {
		defer un(trace(p, "ImportSpec"))
	}

	var ident *ast.Ident
	switch p.tok {
	case token.IDENT:
		ident = p.parseIdent()
	case token.PERIOD:
		ident = &ast.Ident{NamePos: p.pos, Name: "."}
		p.next()
	}

	pos := p.pos
	var path string
	if p.tok == token.STRING {
		path = p.lit
		p.next()
	} else if p.tok.IsLiteral() {
		p.error(pos, "import path must be a string")
		p.next()
	} else {
		p.error(pos, "missing import path")
		p.advance(exprEnd)
	}
	comment := p.expectSemi()

	// collect imports
	spec := &ast.ImportSpec{
		Doc:     doc,
		Name:    ident,
		Path:    &ast.BasicLit{ValuePos: pos, Kind: token.STRING, Value: path},
		Comment: comment,
	}
	p.imports = append(p.imports, spec)

	return spec
}

func (p *parser) parseValueSpec(doc *ast.CommentGroup, keyword token.Token, iota int) ast.Spec {
	if p.trace {
		defer un(trace(p, keyword.String()+"Spec"))
	}

	idents := p.parseIdentList()
	var typ ast.Expr
	var values []ast.Expr
	switch keyword {
	case token.CONST:
		// always permit optional type and initialization for more tolerant parsing
		if p.tok != token.EOF && p.tok != token.SEMICOLON && p.tok != token.RPAREN {
			typ = p.tryIdentOrType()
			if p.tok == token.ASSIGN {
				p.next()
				values = p.parseList(true)
			}
		}
	case token.VAR:
		if p.tok != token.ASSIGN {
			typ = p.parseType()
		}
		if p.tok == token.ASSIGN {
			p.next()
			values = p.parseList(true)
		}
	default:
		panic("unreachable")
	}
	comment := p.expectSemi()

	spec := &ast.ValueSpec{
		Doc:     doc,
		Names:   idents,
		Type:    typ,
		Values:  values,
		Comment: comment,
	}
	return spec
}

func (p *parser) parseGenericType(spec *ast.TypeSpec, openPos token.Pos, name0 *ast.Ident, typ0 ast.Expr) {
	if p.trace {
		defer un(trace(p, "parseGenericType"))
	}

	list := p.parseParameterList(name0, typ0, token.RBRACK)
	closePos := p.expect(token.RBRACK)
	spec.TypeParams = &ast.FieldList{Opening: openPos, List: list, Closing: closePos}
	// Let the type checker decide whether to accept type parameters on aliases:
	// see go.dev/issue/46477.
	if p.tok == token.ASSIGN {
		// type alias
		spec.Assign = p.pos
		p.next()
	}
	spec.Type = p.parseType()
}

func (p *parser) parseTypeSpec(doc *ast.CommentGroup, _ token.Token, _ int) ast.Spec {
	if p.trace {
		defer un(trace(p, "TypeSpec"))
	}

	name := p.parseIdent()
	spec := &ast.TypeSpec{Doc: doc, Name: name}

	if p.tok == token.LBRACK {
		// spec.Name "[" ...
		// array/slice type or type parameter list
		lbrack := p.pos
		p.next()
		if p.tok == token.IDENT {
			// We may have an array type or a type parameter list.
			// In either case we expect an expression x (which may
			// just be a name, or a more complex expression) which
			// we can analyze further.
			//
			// A type parameter list may have a type bound starting
			// with a "[" as in: P []E. In tha
```