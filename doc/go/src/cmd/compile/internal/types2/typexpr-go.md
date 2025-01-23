Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the `typexpr.go` file, what Go feature it implements, examples, potential errors, and treatment of command-line arguments.

2. **Initial Scan and Key Terms:**  Read through the comments and function names. Keywords like "type-checking," "identifiers," "type expressions," `Checker`, `operand`, `syntax.Expr`, `Type`, `generic`, `instantiation`, `array length`, `typeList` immediately stand out. These suggest the core purpose is validating and resolving type information in Go code.

3. **Identify Core Functions:**  Focus on the most prominent functions: `ident`, `typ`, `varType`, `definedType`, `genericType`, `typInternal`, `instantiatedType`, `arrayLength`, `typeList`. These are the workhorses of the file.

4. **Analyze Individual Function Functionality (Micro-Level):**

   * **`ident`:**  Checks if an identifier represents a value or a type. Handles predeclared identifiers, errors for undefined names, and the special blank identifier `_`. It interacts with the `Checker`'s scope management. The `wantType` flag is crucial.
   * **`typ`:** The basic entry point for checking a type expression. It disallows uninstantiated generics.
   * **`varType`:**  Like `typ` but specifically for variable types, adding a check against constraint interfaces being used directly.
   * **`definedType`:**  Similar to `typ`, but used when defining a new type, allowing a `TypeName` to be associated with the expression being checked (important for recursive types).
   * **`genericType`:** Specifically for checking if an expression represents a *generic* type. It provides a `cause` string if the type is valid but not generic.
   * **`typInternal`:**  The core logic for type checking various type expression forms (identifiers, selectors, index expressions for instantiation, array/slice/struct/pointer/function/interface/map/chan types). This function has a large `switch` statement handling different `syntax.Expr` types.
   * **`instantiatedType`:** Handles the process of applying type arguments to a generic type. It verifies the number of arguments and their constraints.
   * **`arrayLength`:**  Specifically checks the expression used for array lengths, ensuring it's a constant integer.
   * **`typeList`:**  Processes a list of expressions, treating them as type expressions.

5. **Infer the High-Level Purpose (Macro-Level):**  Based on the individual function analysis, it's clear this file is responsible for the *semantic analysis* of type-related syntax in Go. It goes beyond just parsing and ensures that type expressions are valid according to Go's type system. This involves resolving identifiers to their declarations, checking type compatibility, handling generics, and enforcing language rules.

6. **Connect to Go Features:** The functions and their logic directly map to Go language features:

   * **Type Declarations:** `definedType`, `typInternal` handle `type MyType int`, `typealias MyAlias = string`.
   * **Variable Declarations:** `varType` is used when declaring variables (`var x int`).
   * **Function Signatures:** `typInternal` handles `func(a int) string`.
   * **Structs and Interfaces:** `typInternal` calls `check.structType` and `check.interfaceType` (though those implementations are in other files).
   * **Pointers, Arrays, Slices, Maps, Channels:**  `typInternal` has cases for these.
   * **Generics:** `genericType`, `instantiatedType`, `typeList` are central to handling generic type declarations and instantiations.

7. **Construct Examples:** Create simple Go code snippets that demonstrate the functionality of the key functions. Focus on showing successful and error cases. For generics, show both definition and instantiation.

8. **Identify Potential Errors:**  Think about common mistakes developers make with types in Go. Undeclared variables/types, using values where types are expected, incorrect number of type arguments for generics, using non-comparable types as map keys, and using constraint interfaces directly are good examples.

9. **Command-Line Arguments:**  Scan the code for any interaction with command-line arguments. Notice the `check.conf.Trace` which suggests a build flag or option that enables tracing. Mention this.

10. **Refine and Structure:** Organize the information logically. Start with a high-level summary, then detail the function functionalities, provide code examples, discuss error scenarios, and finally, touch upon command-line arguments. Use clear and concise language.

11. **Self-Correction/Refinement During the Process:**

    * **Initial thought:** "This is just about parsing types."  **Correction:**  Realize it's *semantic* analysis, ensuring type rules are followed.
    * **During `ident` analysis:**  Note the importance of `wantType` and how it influences error reporting.
    * **During `typInternal` analysis:** Recognize the extensive handling of different `syntax.Expr` types and their mapping to Go type system elements.
    * **While considering generics:**  Emphasize the distinction between generic *definition* and *instantiation*.
    * **Error handling:** Think beyond syntax errors to semantic errors related to type usage.

By following these steps, you can systematically analyze the code and provide a comprehensive answer that addresses all aspects of the prompt. The process involves both a detailed examination of individual components and a broader understanding of the role the code plays within the Go compiler.
这段代码是Go语言编译器 `cmd/compile/internal/types2` 包中负责类型表达式检查的一部分。它的主要功能是**对Go语言源代码中的类型表达式进行语义分析和类型推断**。

以下是它的具体功能分解：

**核心功能：类型表达式的检查和解析**

* **识别各种类型表达式:**  代码能够识别和处理 Go 语言中各种类型的表达式，包括：
    * **标识符 (Identifiers):**  如 `int`, `string`, 自定义的类型名。
    * **选择器表达式 (Selector Expressions):** 如 `pkg.TypeName`。
    * **索引表达式 (Index Expressions):** 用于泛型实例化，如 `List[int]`。
    * **括号表达式 (Paren Expressions):** `(int)`。
    * **数组类型 (Array Types):** `[10]int`, `[...]int`。
    * **切片类型 (Slice Types):** `[]int`。
    * **省略号类型 (Dots Types):** `...` (在参数列表和复合字面量中使用)。
    * **结构体类型 (Struct Types):** `struct { ... }`。
    * **指针类型 (Pointer Types):** `*int`。
    * **函数类型 (Func Types):** `func(int) string`。
    * **接口类型 (Interface Types):** `interface { ... }`。
    * **Map 类型 (Map Types):** `map[string]int`。
    * **通道类型 (Chan Types):** `chan int`, `chan<- int`, `<-chan int`。

* **解析标识符:** `ident` 函数负责解析标识符，它会查找标识符对应的对象（常量、类型、变量、函数、包名等），并根据上下文判断它是否表示一个类型。

* **类型表达式求值:** `typInternal` 函数是类型表达式检查的核心驱动，它根据表达式的语法结构，递归地调用不同的子功能来推断和检查类型。

* **处理泛型:**  `genericType` 和 `instantiatedType` 函数专门用于处理泛型类型。`genericType` 检查表达式是否表示一个泛型类型，`instantiatedType` 则处理泛型类型的实例化过程，检查类型参数是否符合约束。

* **处理 `defined` 类型:** `definedType` 函数用于处理类型声明中定义的类型，它允许在类型定义过程中引用自身，从而支持递归类型。

* **数组长度检查:** `arrayLength` 函数专门用于检查数组声明中的长度表达式，确保它是一个常量整数。

* **类型列表处理:** `typeList` 函数用于处理类型参数列表，返回一个 `Type` 类型的切片。

**实现的 Go 语言功能：类型声明、类型使用、泛型**

这段代码是 Go 语言类型系统实现的关键部分，它支撑了以下核心功能：

1. **类型声明 (Type Declarations):**  例如 `type MyInt int`， `type MyStruct struct { Name string }`，以及包含泛型的类型声明 `type List[T any] []T`。

   ```go
   package main

   type MyInt int

   type Point struct {
       X, Y int
   }

   type StringPair[T any] struct {
       First string
       Second T
   }

   func main() {
       var a MyInt = 10
       var p Point = Point{1, 2}
       var sp StringPair[int] = StringPair[int]{"hello", 42}
       println(a, p.X, sp.Second)
   }
   ```
   **假设输入 (解析 `type MyInt int`)：**  `e` 是指向 `syntax.Name` 节点的指针，其 `Value` 为 "int"， `def` 是指向 `TypeName` 节点的指针，其 `name` 为 "MyInt"。
   **推理输出：** `definedType` 函数会调用 `typInternal`，最终会识别 "int" 是一个预定义的 `Basic` 类型，并将 `MyInt` 的底层类型设置为 `int`。

2. **变量声明中的类型使用 (Type Usage in Variable Declarations):** 例如 `var x int`, `var s []string`, `var m map[string]int`。

   ```go
   package main

   func main() {
       var age int = 30
       var names []string = []string{"Alice", "Bob"}
       var ages map[string]int = map[string]int{"Alice": 30, "Bob": 25}
       println(age, names[0], ages["Alice"])
   }
   ```
   **假设输入 (解析 `var age int`)：** `e` 是指向 `syntax.Name` 节点的指针，其 `Value` 为 "int"。
   **推理输出：** `varType` 函数会调用 `definedType` 和 `typInternal`，最终识别 "int" 是一个预定义的 `Basic` 类型。

3. **泛型类型定义和实例化 (Generic Type Definitions and Instantiations):** 例如 `type List[T any] []T` 和 `var numbers List[int]`。

   ```go
   package main

   type List[T any] []T

   func main() {
       var numbers List[int] = []int{1, 2, 3}
       println(numbers[0])
   }
   ```
   **假设输入 (解析 `List[int]`)：** `e` 是指向 `syntax.IndexExpr` 节点的指针，其 `X` 部分是 `List` 的标识符，`Index` 部分是 `int` 的标识符。
   **推理输出：** `definedType` 会调用 `typInternal`，识别 `List` 是一个泛型类型。然后 `instantiatedType` 会被调用，用 `int` 实例化 `List`，生成新的类型 `List[int]`。

**涉及的代码推理 (结合假设的输入与输出)**

在上面的代码示例中，已经展示了部分代码推理的过程。`Checker` 结构体 (在其他文件中定义) 维护了符号表和类型检查的状态。`ident` 函数会查找标识符，如果找到的是一个 `TypeName`，并且 `wantType` 为 `true`，则认为它表示一个类型。`typInternal` 内部的 `switch` 语句根据不同的语法节点类型进行不同的处理。例如，对于 `*syntax.ArrayType`，它会调用 `arrayLength` 来获取数组长度，并递归地调用 `varType` 来检查数组元素的类型。

**涉及的命令行参数的具体处理**

这段代码本身并不直接处理命令行参数。但是，`check.conf.Trace` 这个字段很可能与编译器的 `-V` 或 `-v` (verbose) 标志相关联。当启用 trace 模式时，编译器会输出更详细的类型检查信息，这可以通过设置相应的构建标签或命令行参数来实现。具体实现可能在调用 `Checker` 的代码中。

**使用者易犯错的点**

* **在期望类型的地方使用值:**  例如，在类型声明或类型转换时使用了变量名而不是类型名。

   ```go
   package main

   func main() {
       age := 30
       // var count age // 错误：age 是一个变量，不是类型
       var count int = age // 正确
       println(count)
   }
   ```
   **错误信息（可能由 `ident` 函数生成）：**  `age is not a type`

* **泛型类型未实例化就使用:**  直接使用泛型类型名而不提供类型参数。

   ```go
   package main

   type List[T any] []T

   func main() {
       // var items List // 错误：List 是一个泛型类型，需要实例化
       var items List[int] // 正确
       println(items == nil)
   }
   ```
   **错误信息（可能由 `definedType` 或 `genericType` 生成）：** `cannot use generic type List without instantiation`

* **泛型实例化时提供错误的类型参数数量:**  提供的类型参数数量与泛型定义的类型形参数量不符。

   ```go
   package main

   type Pair[T, U any] struct {
       First T
       Second U
   }

   func main() {
       // var p Pair[int] {} // 错误：Pair 需要两个类型参数
       var p Pair[int, string] {} // 正确
       println(p)
   }
   ```
   **错误信息（可能由 `instantiatedType` 中的 `validateTArgLen` 生成）：**  类似于 `wrong number of type arguments for Pair, expected 2, got 1`

* **在不允许使用类型约束接口的地方使用接口:**  在变量声明中直接使用包含类型约束的接口。

   ```go
   package main

   type MyInterface interface {
       ~int | ~string
       M()
   }

   func main() {
       // var val MyInterface // 错误：不能直接使用包含类型约束的接口作为变量类型
   }
   ```
   **错误信息（可能由 `validVarType` 生成）：**  类似于 `cannot use type MyInterface outside a type constraint: interface contains type constraints`

这段代码是 Go 语言编译器进行类型检查的核心组成部分，它确保了 Go 程序的类型安全性，是理解 Go 语言类型系统的重要入口。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/typexpr.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements type-checking of identifiers and type expressions.

package types2

import (
	"cmd/compile/internal/syntax"
	"fmt"
	"go/constant"
	. "internal/types/errors"
	"strings"
)

// ident type-checks identifier e and initializes x with the value or type of e.
// If an error occurred, x.mode is set to invalid.
// For the meaning of def, see Checker.definedType, below.
// If wantType is set, the identifier e is expected to denote a type.
func (check *Checker) ident(x *operand, e *syntax.Name, def *TypeName, wantType bool) {
	x.mode = invalid
	x.expr = e

	scope, obj := check.lookupScope(e.Value)
	switch obj {
	case nil:
		if e.Value == "_" {
			check.error(e, InvalidBlank, "cannot use _ as value or type")
		} else if isValidName(e.Value) {
			check.errorf(e, UndeclaredName, "undefined: %s", e.Value)
		}
		return
	case universeComparable:
		if !check.verifyVersionf(e, go1_18, "predeclared %s", e.Value) {
			return // avoid follow-on errors
		}
	}
	// Because the representation of any depends on gotypesalias, we don't check
	// pointer identity here.
	if obj.Name() == "any" && obj.Parent() == Universe {
		if !check.verifyVersionf(e, go1_18, "predeclared %s", e.Value) {
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
		if !check.conf.EnableAlias && check.isBrokenAlias(obj) {
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
		x.mode = nilvalue

	default:
		panic("unreachable")
	}

	x.typ = typ
}

// typ type-checks the type expression e and returns its type, or Typ[Invalid].
// The type must not be an (uninstantiated) generic type.
func (check *Checker) typ(e syntax.Expr) Type {
	return check.definedType(e, nil)
}

// varType type-checks the type expression e and returns its type, or Typ[Invalid].
// The type must not be an (uninstantiated) generic type and it must not be a
// constraint interface.
func (check *Checker) varType(e syntax.Expr) Type {
	typ := check.definedType(e, nil)
	check.validVarType(e, typ)
	return typ
}

// validVarType reports an error if typ is a constraint interface.
// The expression e is used for error reporting, if any.
func (check *Checker) validVarType(e syntax.Expr, typ Type) {
	// If we have a type parameter there's nothing to do.
	if isTypeParam(typ) {
		return
	}

	// We don't want to call under() or complete interfaces while we are in
	// the middle of type-checking parameter declarations that might belong
	// to interface methods. Delay this check to the end of type-checking.
	check.later(func() {
		if t, _ := under(typ).(*Interface); t != nil {
			pos := syntax.StartPos(e)
			tset := computeInterfaceTypeSet(check, pos, t) // TODO(gri) is this the correct position?
			if !tset.IsMethodSet() {
				if tset.comparable {
					check.softErrorf(pos, MisplacedConstraintIface, "cannot use type %s outside a type constraint: interface is (or embeds) comparable", typ)
				} else {
					check.softErrorf(pos, MisplacedConstraintIface, "cannot use type %s outside a type constraint: interface contains type constraints", typ)
				}
			}
		}
	}).describef(e, "check var type %s", typ)
}

// definedType is like typ but also accepts a type name def.
// If def != nil, e is the type specification for the type named def, declared
// in a type declaration, and def.typ.underlying will be set to the type of e
// before any components of e are type-checked.
func (check *Checker) definedType(e syntax.Expr, def *TypeName) Type {
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
func (check *Checker) genericType(e syntax.Expr, cause *string) Type {
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
// removes any occurrences of "types2." from that name.
func goTypeName(typ Type) string {
	return strings.ReplaceAll(fmt.Sprintf("%T", typ), "types2.", "")
}

// typInternal drives type checking of types.
// Must only be called by definedType or genericType.
func (check *Checker) typInternal(e0 syntax.Expr, def *TypeName) (T Type) {
	if check.conf.Trace {
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
	case *syntax.BadExpr:
		// ignore - error reported before

	case *syntax.Name:
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

	case *syntax.SelectorExpr:
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

	case *syntax.IndexExpr:
		check.verifyVersionf(e, go1_18, "type instantiation")
		return check.instantiatedType(e.X, syntax.UnpackListExpr(e.Index), def)

	case *syntax.ParenExpr:
		// Generic types must be instantiated before they can be used in any form.
		// Consequently, generic types cannot be parenthesized.
		return check.definedType(e.X, def)

	case *syntax.ArrayType:
		typ := new(Array)
		setDefType(def, typ)
		if e.Len != nil {
			typ.len = check.arrayLength(e.Len)
		} else {
			// [...]array
			check.error(e, BadDotDotDotSyntax, "invalid use of [...] array (outside a composite literal)")
			typ.len = -1
		}
		typ.elem = check.varType(e.Elem)
		if typ.len >= 0 {
			return typ
		}
		// report error if we encountered [...]

	case *syntax.SliceType:
		typ := new(Slice)
		setDefType(def, typ)
		typ.elem = check.varType(e.Elem)
		return typ

	case *syntax.DotsType:
		// dots are handled explicitly where they are legal
		// (array composite literals and parameter lists)
		check.error(e, InvalidDotDotDot, "invalid use of '...'")
		check.use(e.Elem)

	case *syntax.StructType:
		typ := new(Struct)
		setDefType(def, typ)
		check.structType(typ, e)
		return typ

	case *syntax.Operation:
		if e.Op == syntax.Mul && e.Y == nil {
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
		}

		check.errorf(e0, NotAType, "%s is not a type", e0)
		check.use(e0)

	case *syntax.FuncType:
		typ := new(Signature)
		setDefType(def, typ)
		check.funcType(typ, nil, nil, e)
		return typ

	case *syntax.InterfaceType:
		typ := check.newInterface()
		setDefType(def, typ)
		check.interfaceType(typ, e, def)
		return typ

	case *syntax.MapType:
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

	case *syntax.ChanType:
		typ := new(Chan)
		setDefType(def, typ)

		dir := SendRecv
		switch e.Dir {
		case 0:
			// nothing to do
		case syntax.SendOnly:
			dir = SendOnly
		case syntax.RecvOnly:
			dir = RecvOnly
		default:
			check.errorf(e, InvalidSyntaxTree, "unknown channel direction %d", e.Dir)
			// ok to continue
		}

		typ.dir = dir
		typ.elem = check.varType(e.Elem)
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
				panic(sprintf(nil, true, "t.fromRHS = %s, typ = %s\n", t.fromRHS, typ))
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

func (check *Checker) instantiatedType(x syntax.Expr, xlist []syntax.Expr, def *TypeName) (res Type) {
	if check.conf.Trace {
		check.trace(x.Pos(), "-- instantiating type %s with %s", x, xlist)
		check.indent++
		defer func() {
			check.indent--
			// Don't format the underlying here. It will always be nil.
			check.trace(x.Pos(), "=> %s", res)
		}()
	}

	defer func() {
		setDefType(def, res)
	}()

	var cause string
	typ := check.genericType(x, &cause)
	if cause != "" {
		check.errorf(x, NotAGenericType, invalidOp+"%s%s (%s)", x, xlist, cause)
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
	targs := check.typeList(xlist)
	if targs == nil {
		return Typ[Invalid]
	}

	// create instance
	// The instance is not generic anymore as it has type arguments, but it still
	// satisfies the genericType interface because it has type parameters, too.
	inst := check.instance(x.Pos(), gtyp, targs, nil, check.context()).(genericType)

	// For Named types, orig.tparams may not be set up, so we need to do expansion later.
	check.later(func() {
		// This is an instance from the source, not from recursive substitution,
		// and so it must be resolved during type-checking so that we can report
		// errors.
		check.recordInstance(x, targs, inst)

		name := inst.(interface{ Obj() *TypeName }).Obj().name
		tparams := inst.TypeParams().list()
		if check.validateTArgLen(x.Pos(), name, len(tparams), len(targs)) {
			// check type constraints
			if i, err := check.verify(x.Pos(), inst.TypeParams().list(), targs, check.context()); err != nil {
				// best position for error reporting
				pos := x.Pos()
				if i < len(xlist) {
					pos = syntax.StartPos(xlist[i])
				}
				check.softErrorf(pos, InvalidTypeArg, "%s", err)
			} else {
				check.mono.recordInstance(check.pkg, x.Pos(), tparams, targs, xlist)
			}
		}
	}).describef(x, "verify instantiation %s", inst)

	return inst
}

// arrayLength type-checks the array length expression e
// and returns the constant length >= 0, or a value < 0
// to indicate an error (and thus an unknown length).
func (check *Checker) arrayLength(e syntax.Expr) int64 {
	// If e is an identifier, the array declaration might be an
	// attempt at a parameterized type declaration with missing
	// constraint. Provide an error message that mentions array
	// length.
	if name, _ := e.(*syntax.Name); name != nil {
		obj := check.lookup(name.Value)
		if obj == nil {
			check.errorf(name, InvalidArrayLen, "undefined array length %s or missing type constraint", name.Value)
			return -1
		}
		if _, ok := obj.(*Const); !ok {
			check.errorf(name, InvalidArrayLen, "invalid array length %s", name.Value)
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
func (check *Checker) typeList(list []syntax.Expr) []Type {
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
```