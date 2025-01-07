Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - The Big Picture:**

The first step is to recognize the package and file name: `go/src/go/types/typexpr.go`. This immediately tells us we're dealing with the `go/types` package, which is responsible for type checking in the Go compiler. The filename `typexpr.go` strongly suggests it handles the parsing and validation of type expressions.

**2. Core Functions - Identifying Key Actions:**

Next, I scan the code for the main functions. Functions like `ident`, `typ`, `varType`, `definedType`, `genericType`, and `instantiatedType` stand out. Their names clearly indicate their purpose:

* `ident`: Handles identifiers, potentially representing variables, constants, or types.
* `typ`:  Checks if an expression is a valid type.
* `varType`: Similar to `typ`, but with extra constraints for variable types.
* `definedType`:  Checks a type expression, especially when defining a new named type.
* `genericType`: Specifically deals with generic types.
* `instantiatedType`: Handles the instantiation of generic types.

These are the primary verbs of the file, revealing the core functionalities.

**3. Analyzing Individual Functions - Deeper Dive:**

Now, I examine each core function in more detail:

* **`ident`:**  I notice the checks for undeclared names, the handling of the blank identifier `_`, and the distinction between wanting a value or a type. The logic around `obj.Type()` and `check.objDecl` is important – it shows how the type checker resolves the type of an identifier. The handling of package names and different kinds of objects (`Const`, `TypeName`, `Var`, etc.) is also significant.

* **`typ`, `varType`, `definedType`:** These functions seem to build on each other. `definedType` calls `typInternal`, and `varType` calls `definedType` with extra validation. This suggests a layered approach to type checking. The error handling for using generic types without instantiation is also noticeable.

* **`genericType`:** This function explicitly checks for generic types. The `cause` parameter indicates how it handles the case where an expected generic type isn't found.

* **`instantiatedType`:**  The name itself is a strong clue. The code confirms this by showing how type arguments are evaluated (`check.typeList`) and how the instantiation process (`check.instance`) occurs. The error handling related to the number of type arguments and constraint verification is important.

* **Helper Functions:** I also observe helper functions like `goTypeName`, `setDefType`, `arrayLength`, and `typeList`. These perform specific, smaller tasks that support the main functions.

**4. Identifying Go Language Features:**

Based on the function names and their internal logic, I can deduce the Go language features this code is related to:

* **Type Declarations:** The `definedType` function and the handling of `TypeName` objects directly relate to how Go defines new types.
* **Type Expressions:** The entire file focuses on parsing and validating various type expressions (identifiers, selectors, array types, struct types, function types, interface types, map types, channel types, pointer types).
* **Generics (Type Parameters and Instantiation):** The presence of `genericType`, `instantiatedType`, `TypeParams`, and the checks for type argument counts and constraints clearly point to Go's generics feature.
* **Composite Literals (Indirectly):**  The handling of `[...]` in array types, although generating an error in this context, is related to the syntax used in composite literals.
* **Interfaces:** The `InterfaceType` case and the `validVarType` function's check for constraint interfaces are relevant to interfaces.
* **Constants:** The `arrayLength` function and the handling of `Const` objects show how constant expressions are used for array lengths.
* **Packages and Selectors:** The `selector` function (even though its code isn't shown here, its mention in `ident`) and the handling of `PkgName` objects are related to accessing members of packages.

**5. Inferring Functionality with Code Examples:**

To solidify the understanding, I mentally construct or write small Go code examples that would trigger the logic within these functions. This helps in visualizing how the type checker would process different scenarios. For instance, an example with a generic type instantiation, a type alias, or a simple type declaration.

**6. Identifying Potential Errors (User Mistakes):**

By analyzing the error messages generated within the code (`check.errorf`), I can anticipate common mistakes users might make. Examples include:

* Using a non-type as a type.
* Trying to use a generic type without providing type arguments.
* Providing the wrong number of type arguments.
* Using a non-constant expression for array length.
* Using a non-comparable type as a map key.
* Misusing the blank identifier `_`.

**7. Considering Command-Line Arguments (If Applicable):**

Although this specific code snippet doesn't directly handle command-line arguments, I know that the broader `go/types` package is used by the `go build`, `go run`, and `go vet` commands. Therefore, any type-checking errors identified by this code would eventually be surfaced through the output of these commands.

**8. Structuring the Answer:**

Finally, I organize my findings into a clear and structured answer, using headings and bullet points for readability. I aim to explain the functionality in plain language, provide illustrative Go code examples, and highlight potential pitfalls for users. The use of specific error messages from the code helps in making the explanation more concrete.

This iterative process of reading, analyzing, inferring, and validating with examples allows for a comprehensive understanding of the given Go code snippet and its role in the larger Go type system.
这段代码是 Go 语言 `go/types` 包中 `typexpr.go` 文件的一部分，其主要功能是**对 Go 语言中的类型表达式进行类型检查**。它负责解析和验证各种表示类型的语法结构，确保它们在语义上是正确的。

更具体地说，它涵盖了以下几个核心功能：

1. **标识符的类型检查 (`ident` 函数):**
   - 识别并解析标识符，判断它代表的是类型、常量、变量、函数还是包名等。
   - 查找标识符在其作用域中的声明。
   - 检查标识符是否被正确使用（例如，不能将 `_` 用作类型或值）。
   - 记录标识符的使用情况，用于后续的 "未使用的声明" 检查。

2. **类型表达式的类型检查 (`typ`, `varType`, `definedType`, `genericType`, `instantiatedType` 函数):**
   - 解析各种类型表达式，如基本类型（`int`, `string`）、复合类型（`[]int`, `map[string]int`）、指针类型（`*int`）、函数类型（`func(int) string`）、接口类型（`interface{}`）、通道类型（`chan int`）以及结构体类型（`struct{}`）。
   - 递归地检查类型表达式的组成部分。
   - 检查类型参数的有效性（对于泛型）。
   - 处理类型实例化（将泛型类型与具体的类型参数绑定）。
   - 检查类型是否可用于变量声明（`varType` 会额外检查接口是否为约束接口）。

3. **数组长度的类型检查 (`arrayLength` 函数):**
   - 检查数组长度表达式是否为常量整数。
   - 报告无效的数组长度。

4. **类型列表的解析 (`typeList` 函数):**
   - 将一系列表达式解析为类型列表，用于泛型实例化等场景。

**可以推理出它是什么 Go 语言功能的实现：**

基于以上功能，可以推断 `typexpr.go` 文件是 Go 语言**类型系统**和**泛型**功能实现的核心部分。它负责理解和验证用户在代码中声明和使用的各种类型，确保 Go 程序的类型安全。

**Go 代码举例说明:**

```go
package main

type MyInt int
type StringPair [2]string

type MyMap map[string]int

type MyFunc func(int) bool

type MyInterface interface {
	DoSomething()
}

type GenericType[T any] struct {
	Value T
}

func main() {
	var a int        // 基本类型
	var b MyInt      // 类型别名
	var c []string   // 切片类型
	var d StringPair // 数组类型
	var e MyMap      // Map 类型
	var f MyFunc     // 函数类型
	var g MyInterface // 接口类型
	var h *int       // 指针类型
	var i chan int   // 通道类型
	var j struct {   // 结构体类型
		Name string
		Age  int
	}
	var k GenericType[int] // 泛型实例化
}
```

当 Go 编译器在编译上述代码时，`go/types` 包中的代码（包括 `typexpr.go`）会负责检查 `int`, `MyInt`, `[]string`, `StringPair`, `map[string]int` 等类型表达式的合法性，以及泛型类型 `GenericType[int]` 的实例化过程。

**代码推理示例 (假设的输入与输出):**

假设 `ident` 函数接收到一个 AST 节点，表示标识符 "MyInt"，且当前作用域中 "MyInt" 被声明为一个类型别名：

**假设输入:**

- `e`:  `*ast.Ident{Name: "MyInt"}`
- `def`: `nil` (不是在类型声明的右侧)
- `wantType`: `true` (期望得到一个类型)

**`ident` 函数的内部推理 (简化):**

1. 在当前作用域中查找 "MyInt"，找到对应的 `TypeName` 对象。
2. 检查该 `TypeName` 对象是否表示一个类型 (是的)。
3. 将 `x.mode` 设置为 `typexpr`。
4. 将 `x.typ` 设置为 "MyInt" 对应的类型（可能是 `types.Named`）。

**假设输出:**

- `x.mode`: `typexpr`
- `x.typ`:  `types.Named{Obj: &TypeName{Name: "MyInt", ...}, Underlying: types.Basic{Kind: types.Int, ...}}` (简化表示)

**如果 `ident` 接收到的标识符未声明：**

**假设输入:**

- `e`: `*ast.Ident{Name: "NotDefinedType"}`
- `def`: `nil`
- `wantType`: `true`

**`ident` 函数的内部推理 (简化):**

1. 在当前作用域中查找 "NotDefinedType"，未找到。
2. 报告一个 "未声明的名称" 的错误。
3. 将 `x.mode` 设置为 `invalid`。

**假设输出:**

- `x.mode`: `invalid`
- 编译器会输出类似 "undefined: NotDefinedType" 的错误信息。

**命令行参数的具体处理:**

`go/types` 包本身通常不直接处理命令行参数。它是 Go 编译器 `cmd/compile` 等工具的一部分。编译器会解析 Go 源代码，构建抽象语法树 (AST)，然后使用 `go/types` 包进行类型检查。命令行参数会影响编译器的行为（例如，指定 Go 版本），这些行为可能会间接影响 `go/types` 的类型检查过程，例如是否启用泛型特性。

例如，使用 `-lang=go1.17` 编译包含泛型代码的程序将会导致编译错误，因为 Go 1.17 不支持泛型。`go/types` 包会根据编译器的配置（可能基于命令行参数）来决定如何处理泛型相关的类型表达式。

**使用者易犯错的点 (针对 `typexpr.go` 负责的功能):**

1. **将非类型的值当作类型使用:**

   ```go
   package main

   var count int

   func main() {
       var x count // 错误：count 是一个变量，不是类型
   }
   ```

   `ident` 函数会识别出 `count` 是一个变量，而不是类型，并报告错误。

2. **在需要类型参数时忘记提供:**

   ```go
   package main

   type GenericType[T any] struct {
       Value T
   }

   func main() {
       var x GenericType // 错误：GenericType 需要类型参数
   }
   ```

   `genericType` 或 `instantiatedType` 函数会检测到缺少类型参数，并报告 "cannot use generic type GenericType without instantiation" 的错误。

3. **提供错误数量的类型参数:**

   ```go
   package main

   type GenericType[T any, U int] struct {
       Value1 T
       Value2 U
   }

   func main() {
       var x GenericType[int] // 错误：需要两个类型参数
   }
   ```

   `instantiatedType` 函数会检查类型参数的数量是否匹配，并报告错误。

4. **使用非常量表达式作为数组长度:**

   ```go
   package main

   var size int = 10

   func main() {
       var arr [size]int // 错误：数组长度必须是常量
   }
   ```

   `arrayLength` 函数会检查数组长度表达式的值，发现它不是常量，并报告错误。

5. **在映射的键类型中使用不可比较的类型:**

   ```go
   package main

   func main() {
       var m map[[]int]string // 错误：切片是不可比较的
   }
   ```

   `typInternal` 函数在处理 `MapType` 时，会检查键类型是否可比较。

这段代码在 Go 语言的类型检查过程中扮演着至关重要的角色，确保了代码的类型安全性，并且对 Go 语言的泛型功能的正确实现起着核心作用。理解其功能有助于我们更好地理解 Go 语言的类型系统和编译过程。

Prompt: 
```
这是路径为go/src/go/types/typexpr.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements type-checking of identifiers and type expressions.

package types

import (
	"fmt"
	"go/ast"
	"go/constant"
	. "internal/types/errors"
	"strings"
)

// ident type-checks identifier e and initializes x with the value or type of e.
// If an error occurred, x.mode is set to invalid.
// For the meaning of def, see Checker.definedType, below.
// If wantType is set, the identifier e is expected to denote a type.
func (check *Checker) ident(x *operand, e *ast.Ident, def *TypeName, wantType bool) {
	x.mode = invalid
	x.expr = e

	scope, obj := check.lookupScope(e.Name)
	switch obj {
	case nil:
		if e.Name == "_" {
			check.error(e, InvalidBlank, "cannot use _ as value or type")
		} else if isValidName(e.Name) {
			check.errorf(e, UndeclaredName, "undefined: %s", e.Name)
		}
		return
	case universeComparable:
		if !check.verifyVersionf(e, go1_18, "predeclared %s", e.Name) {
			return // avoid follow-on errors
		}
	}
	// Because the representation of any depends on gotypesalias, we don't check
	// pointer identity here.
	if obj.Name() == "any" && obj.Parent() == Universe {
		if !check.verifyVersionf(e, go1_18, "predeclared %s", e.Name) {
			return // avoid follow-on errors
		}
	}
	check.recordUse(e, obj)

	// If we want a type but don't have one, stop right here and avoid potential problems
	// with missing underlying types. This also gives better error messages in some cases
	// (see go.dev/issue/65344).
	_, gotType := obj.(*TypeName)
	if !gotType && wantType {
		check.errorf(e, NotAType, "%s is not a type", obj.Name())
		// avoid "declared but not used" errors
		// (don't use Checker.use - we don't want to evaluate too much)
		if v, _ := obj.(*Var); v != nil && v.pkg == check.pkg /* see Checker.use1 */ {
			v.used = true
		}
		return
	}

	// Type-check the object.
	// Only call Checker.objDecl if the object doesn't have a type yet
	// (in which case we must actually determine it) or the object is a
	// TypeName from the current package and we also want a type (in which case
	// we might detect a cycle which needs to be reported). Otherwise we can skip
	// the call and avoid a possible cycle error in favor of the more informative
	// "not a type/value" error that this function's caller will issue (see
	// go.dev/issue/25790).
	//
	// Note that it is important to avoid calling objDecl on objects from other
	// packages, to avoid races: see issue #69912.
	typ := obj.Type()
	if typ == nil || (gotType && wantType && obj.Pkg() == check.pkg) {
		check.objDecl(obj, def)
		typ = obj.Type() // type must have been assigned by Checker.objDecl
	}
	assert(typ != nil)

	// The object may have been dot-imported.
	// If so, mark the respective package as used.
	// (This code is only needed for dot-imports. Without them,
	// we only have to mark variables, see *Var case below).
	if pkgName := check.dotImportMap[dotImportKey{scope, obj.Name()}]; pkgName != nil {
		pkgName.used = true
	}

	switch obj := obj.(type) {
	case *PkgName:
		check.errorf(e, InvalidPkgUse, "use of package %s not in selector", obj.name)
		return

	case *Const:
		check.addDeclDep(obj)
		if !isValid(typ) {
			return
		}
		if obj == universeIota {
			if check.iota == nil {
				check.error(e, InvalidIota, "cannot use iota outside constant declaration")
				return
			}
			x.val = check.iota
		} else {
			x.val = obj.val
		}
		assert(x.val != nil)
		x.mode = constant_

	case *TypeName:
		if !check.conf._EnableAlias && check.isBrokenAlias(obj) {
			check.errorf(e, InvalidDeclCycle, "invalid use of type alias %s in recursive type (see go.dev/issue/50729)", obj.name)
			return
		}
		x.mode = typexpr

	case *Var:
		// It's ok to mark non-local variables, but ignore variables
		// from other packages to avoid potential race conditions with
		// dot-imported variables.
		if obj.pkg == check.pkg {
			obj.used = true
		}
		check.addDeclDep(obj)
		if !isValid(typ) {
			return
		}
		x.mode = variable

	case *Func:
		check.addDeclDep(obj)
		x.mode = value

	case *Builtin:
		x.id = obj.id
		x.mode = builtin

	case *Nil:
		x.mode = value

	default:
		panic("unreachable")
	}

	x.typ = typ
}

// typ type-checks the type expression e and returns its type, or Typ[Invalid].
// The type must not be an (uninstantiated) generic type.
func (check *Checker) typ(e ast.Expr) Type {
	return check.definedType(e, nil)
}

// varType type-checks the type expression e and returns its type, or Typ[Invalid].
// The type must not be an (uninstantiated) generic type and it must not be a
// constraint interface.
func (check *Checker) varType(e ast.Expr) Type {
	typ := check.definedType(e, nil)
	check.validVarType(e, typ)
	return typ
}

// validVarType reports an error if typ is a constraint interface.
// The expression e is used for error reporting, if any.
func (check *Checker) validVarType(e ast.Expr, typ Type) {
	// If we have a type parameter there's nothing to do.
	if isTypeParam(typ) {
		return
	}

	// We don't want to call under() or complete interfaces while we are in
	// the middle of type-checking parameter declarations that might belong
	// to interface methods. Delay this check to the end of type-checking.
	check.later(func() {
		if t, _ := under(typ).(*Interface); t != nil {
			tset := computeInterfaceTypeSet(check, e.Pos(), t) // TODO(gri) is this the correct position?
			if !tset.IsMethodSet() {
				if tset.comparable {
					check.softErrorf(e, MisplacedConstraintIface, "cannot use type %s outside a type constraint: interface is (or embeds) comparable", typ)
				} else {
					check.softErrorf(e, MisplacedConstraintIface, "cannot use type %s outside a type constraint: interface contains type constraints", typ)
				}
			}
		}
	}).describef(e, "check var type %s", typ)
}

// definedType is like typ but also accepts a type name def.
// If def != nil, e is the type specification for the type named def, declared
// in a type declaration, and def.typ.underlying will be set to the type of e
// before any components of e are type-checked.
func (check *Checker) definedType(e ast.Expr, def *TypeName) Type {
	typ := check.typInternal(e, def)
	assert(isTyped(typ))
	if isGeneric(typ) {
		check.errorf(e, WrongTypeArgCount, "cannot use generic type %s without instantiation", typ)
		typ = Typ[Invalid]
	}
	check.recordTypeAndValue(e, typexpr, typ, nil)
	return typ
}

// genericType is like typ but the type must be an (uninstantiated) generic
// type. If cause is non-nil and the type expression was a valid type but not
// generic, cause will be populated with a message describing the error.
//
// Note: If the type expression was invalid and an error was reported before,
// cause will not be populated; thus cause alone cannot be used to determine
// if an error occurred.
func (check *Checker) genericType(e ast.Expr, cause *string) Type {
	typ := check.typInternal(e, nil)
	assert(isTyped(typ))
	if isValid(typ) && !isGeneric(typ) {
		if cause != nil {
			*cause = check.sprintf("%s is not a generic type", typ)
		}
		typ = Typ[Invalid]
	}
	// TODO(gri) what is the correct call below?
	check.recordTypeAndValue(e, typexpr, typ, nil)
	return typ
}

// goTypeName returns the Go type name for typ and
// removes any occurrences of "types." from that name.
func goTypeName(typ Type) string {
	return strings.ReplaceAll(fmt.Sprintf("%T", typ), "types.", "")
}

// typInternal drives type checking of types.
// Must only be called by definedType or genericType.
func (check *Checker) typInternal(e0 ast.Expr, def *TypeName) (T Type) {
	if check.conf._Trace {
		check.trace(e0.Pos(), "-- type %s", e0)
		check.indent++
		defer func() {
			check.indent--
			var under Type
			if T != nil {
				// Calling under() here may lead to endless instantiations.
				// Test case: type T[P any] *T[P]
				under = safeUnderlying(T)
			}
			if T == under {
				check.trace(e0.Pos(), "=> %s // %s", T, goTypeName(T))
			} else {
				check.trace(e0.Pos(), "=> %s (under = %s) // %s", T, under, goTypeName(T))
			}
		}()
	}

	switch e := e0.(type) {
	case *ast.BadExpr:
		// ignore - error reported before

	case *ast.Ident:
		var x operand
		check.ident(&x, e, def, true)

		switch x.mode {
		case typexpr:
			typ := x.typ
			setDefType(def, typ)
			return typ
		case invalid:
			// ignore - error reported before
		case novalue:
			check.errorf(&x, NotAType, "%s used as type", &x)
		default:
			check.errorf(&x, NotAType, "%s is not a type", &x)
		}

	case *ast.SelectorExpr:
		var x operand
		check.selector(&x, e, def, true)

		switch x.mode {
		case typexpr:
			typ := x.typ
			setDefType(def, typ)
			return typ
		case invalid:
			// ignore - error reported before
		case novalue:
			check.errorf(&x, NotAType, "%s used as type", &x)
		default:
			check.errorf(&x, NotAType, "%s is not a type", &x)
		}

	case *ast.IndexExpr, *ast.IndexListExpr:
		ix := unpackIndexedExpr(e)
		check.verifyVersionf(inNode(e, ix.lbrack), go1_18, "type instantiation")
		return check.instantiatedType(ix, def)

	case *ast.ParenExpr:
		// Generic types must be instantiated before they can be used in any form.
		// Consequently, generic types cannot be parenthesized.
		return check.definedType(e.X, def)

	case *ast.ArrayType:
		if e.Len == nil {
			typ := new(Slice)
			setDefType(def, typ)
			typ.elem = check.varType(e.Elt)
			return typ
		}

		typ := new(Array)
		setDefType(def, typ)
		// Provide a more specific error when encountering a [...] array
		// rather than leaving it to the handling of the ... expression.
		if _, ok := e.Len.(*ast.Ellipsis); ok {
			check.error(e.Len, BadDotDotDotSyntax, "invalid use of [...] array (outside a composite literal)")
			typ.len = -1
		} else {
			typ.len = check.arrayLength(e.Len)
		}
		typ.elem = check.varType(e.Elt)
		if typ.len >= 0 {
			return typ
		}
		// report error if we encountered [...]

	case *ast.Ellipsis:
		// dots are handled explicitly where they are legal
		// (array composite literals and parameter lists)
		check.error(e, InvalidDotDotDot, "invalid use of '...'")
		check.use(e.Elt)

	case *ast.StructType:
		typ := new(Struct)
		setDefType(def, typ)
		check.structType(typ, e)
		return typ

	case *ast.StarExpr:
		typ := new(Pointer)
		typ.base = Typ[Invalid] // avoid nil base in invalid recursive type declaration
		setDefType(def, typ)
		typ.base = check.varType(e.X)
		// If typ.base is invalid, it's unlikely that *base is particularly
		// useful - even a valid dereferenciation will lead to an invalid
		// type again, and in some cases we get unexpected follow-on errors
		// (e.g., go.dev/issue/49005). Return an invalid type instead.
		if !isValid(typ.base) {
			return Typ[Invalid]
		}
		return typ

	case *ast.FuncType:
		typ := new(Signature)
		setDefType(def, typ)
		check.funcType(typ, nil, e)
		return typ

	case *ast.InterfaceType:
		typ := check.newInterface()
		setDefType(def, typ)
		check.interfaceType(typ, e, def)
		return typ

	case *ast.MapType:
		typ := new(Map)
		setDefType(def, typ)

		typ.key = check.varType(e.Key)
		typ.elem = check.varType(e.Value)

		// spec: "The comparison operators == and != must be fully defined
		// for operands of the key type; thus the key type must not be a
		// function, map, or slice."
		//
		// Delay this check because it requires fully setup types;
		// it is safe to continue in any case (was go.dev/issue/6667).
		check.later(func() {
			if !Comparable(typ.key) {
				var why string
				if isTypeParam(typ.key) {
					why = " (missing comparable constraint)"
				}
				check.errorf(e.Key, IncomparableMapKey, "invalid map key type %s%s", typ.key, why)
			}
		}).describef(e.Key, "check map key %s", typ.key)

		return typ

	case *ast.ChanType:
		typ := new(Chan)
		setDefType(def, typ)

		dir := SendRecv
		switch e.Dir {
		case ast.SEND | ast.RECV:
			// nothing to do
		case ast.SEND:
			dir = SendOnly
		case ast.RECV:
			dir = RecvOnly
		default:
			check.errorf(e, InvalidSyntaxTree, "unknown channel direction %d", e.Dir)
			// ok to continue
		}

		typ.dir = dir
		typ.elem = check.varType(e.Value)
		return typ

	default:
		check.errorf(e0, NotAType, "%s is not a type", e0)
		check.use(e0)
	}

	typ := Typ[Invalid]
	setDefType(def, typ)
	return typ
}

func setDefType(def *TypeName, typ Type) {
	if def != nil {
		switch t := def.typ.(type) {
		case *Alias:
			// t.fromRHS should always be set, either to an invalid type
			// in the beginning, or to typ in certain cyclic declarations.
			if t.fromRHS != Typ[Invalid] && t.fromRHS != typ {
				panic(sprintf(nil, nil, true, "t.fromRHS = %s, typ = %s\n", t.fromRHS, typ))
			}
			t.fromRHS = typ
		case *Basic:
			assert(t == Typ[Invalid])
		case *Named:
			t.underlying = typ
		default:
			panic(fmt.Sprintf("unexpected type %T", t))
		}
	}
}

func (check *Checker) instantiatedType(ix *indexedExpr, def *TypeName) (res Type) {
	if check.conf._Trace {
		check.trace(ix.Pos(), "-- instantiating type %s with %s", ix.x, ix.indices)
		check.indent++
		defer func() {
			check.indent--
			// Don't format the underlying here. It will always be nil.
			check.trace(ix.Pos(), "=> %s", res)
		}()
	}

	defer func() {
		setDefType(def, res)
	}()

	var cause string
	typ := check.genericType(ix.x, &cause)
	if cause != "" {
		check.errorf(ix.orig, NotAGenericType, invalidOp+"%s (%s)", ix.orig, cause)
	}
	if !isValid(typ) {
		return typ // error already reported
	}
	// typ must be a generic Alias or Named type (but not a *Signature)
	if _, ok := typ.(*Signature); ok {
		panic("unexpected generic signature")
	}
	gtyp := typ.(genericType)

	// evaluate arguments
	targs := check.typeList(ix.indices)
	if targs == nil {
		return Typ[Invalid]
	}

	// create instance
	// The instance is not generic anymore as it has type arguments, but it still
	// satisfies the genericType interface because it has type parameters, too.
	inst := check.instance(ix.Pos(), gtyp, targs, nil, check.context()).(genericType)

	// For Named types, orig.tparams may not be set up, so we need to do expansion later.
	check.later(func() {
		// This is an instance from the source, not from recursive substitution,
		// and so it must be resolved during type-checking so that we can report
		// errors.
		check.recordInstance(ix.orig, targs, inst)

		name := inst.(interface{ Obj() *TypeName }).Obj().name
		tparams := inst.TypeParams().list()
		if check.validateTArgLen(ix.Pos(), name, len(tparams), len(targs)) {
			// check type constraints
			if i, err := check.verify(ix.Pos(), inst.TypeParams().list(), targs, check.context()); err != nil {
				// best position for error reporting
				pos := ix.Pos()
				if i < len(ix.indices) {
					pos = ix.indices[i].Pos()
				}
				check.softErrorf(atPos(pos), InvalidTypeArg, "%v", err)
			} else {
				check.mono.recordInstance(check.pkg, ix.Pos(), tparams, targs, ix.indices)
			}
		}
	}).describef(ix, "verify instantiation %s", inst)

	return inst
}

// arrayLength type-checks the array length expression e
// and returns the constant length >= 0, or a value < 0
// to indicate an error (and thus an unknown length).
func (check *Checker) arrayLength(e ast.Expr) int64 {
	// If e is an identifier, the array declaration might be an
	// attempt at a parameterized type declaration with missing
	// constraint. Provide an error message that mentions array
	// length.
	if name, _ := e.(*ast.Ident); name != nil {
		obj := check.lookup(name.Name)
		if obj == nil {
			check.errorf(name, InvalidArrayLen, "undefined array length %s or missing type constraint", name.Name)
			return -1
		}
		if _, ok := obj.(*Const); !ok {
			check.errorf(name, InvalidArrayLen, "invalid array length %s", name.Name)
			return -1
		}
	}

	var x operand
	check.expr(nil, &x, e)
	if x.mode != constant_ {
		if x.mode != invalid {
			check.errorf(&x, InvalidArrayLen, "array length %s must be constant", &x)
		}
		return -1
	}

	if isUntyped(x.typ) || isInteger(x.typ) {
		if val := constant.ToInt(x.val); val.Kind() == constant.Int {
			if representableConst(val, check, Typ[Int], nil) {
				if n, ok := constant.Int64Val(val); ok && n >= 0 {
					return n
				}
			}
		}
	}

	var msg string
	if isInteger(x.typ) {
		msg = "invalid array length %s"
	} else {
		msg = "array length %s must be integer"
	}
	check.errorf(&x, InvalidArrayLen, msg, &x)
	return -1
}

// typeList provides the list of types corresponding to the incoming expression list.
// If an error occurred, the result is nil, but all list elements were type-checked.
func (check *Checker) typeList(list []ast.Expr) []Type {
	res := make([]Type, len(list)) // res != nil even if len(list) == 0
	for i, x := range list {
		t := check.varType(x)
		if !isValid(t) {
			res = nil
		}
		if res != nil {
			res[i] = t
		}
	}
	return res
}

"""



```