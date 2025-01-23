Response: Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Goal:** The core request is to understand the *functionality* of the `predicates.go` file within the `types2` package of the Go compiler. The prompts specifically ask about Go language features, code examples, input/output, command-line arguments, and potential pitfalls.

2. **Initial Scan and Grouping:** Read through the code, identifying the main groups of functions. The comments and function names are very helpful here. We can see clear groupings around:
    * Basic type checks (`isValid`, `isBoolean`, `isInteger`, etc.)
    * "All" type checks for type parameters (`allBoolean`, `allInteger`, etc.)
    * Type classification (`hasName`, `isTypeLit`, `isTyped`, `isUntyped`, etc.)
    * Interface-related checks (`IsInterface`, `isNonTypeParamInterface`, `isTypeParam`, `hasEmptyTypeset`)
    * Generics (`isGeneric`)
    * Comparability (`Comparable`, `comparableType`)
    * Nil checks (`hasNil`)
    * Package comparison (`samePkg`)
    * Type identity (`comparer`, `identical`, `identicalOrigin`, `identicalInstance`)
    * Default type determination (`Default`)
    * "Largest" type (`maxType`)
    * Utility functions (`clone`, `isValidName`)

3. **Analyze Each Function/Group:**  Go through each function (or logical group of functions) and determine its purpose. Consider:
    * **Input:** What type of arguments does it take?  (Often `Type`)
    * **Output:** What does it return? (Often `bool` or `Type`)
    * **Logic:** What are the core operations? (Type assertions, bitwise operations, comparisons, recursive calls)
    * **Comments:** Pay close attention to the comments, especially those explaining subtleties or edge cases (like type parameters).

4. **Identify Key Concepts:** Recognize the underlying Go language features being addressed. In this file, the primary focus is on *type system concepts*:
    * **Basic Types:** `int`, `string`, `bool`, `float64`, etc.
    * **Composite Types:** `struct`, `slice`, `array`, `map`, `chan`, `interface`, `pointer`, `function` (signature).
    * **Named Types:** Types defined with `type` declarations.
    * **Type Parameters (Generics):**  How to check properties of types that are placeholders.
    * **Untyped Constants:**  Special kinds of constants that can implicitly convert.
    * **Interfaces and Type Sets:** How interfaces define contracts.
    * **Comparability:** What types can be compared using `==` and `!=`.
    * **Nil:** Which types can have a nil value.

5. **Infer Go Feature Implementation:**  Based on the function names and logic, deduce which Go language features are being implemented. For example:
    * The `is...` functions are clearly about checking the *kind* of a type.
    * The `all...` functions strongly suggest handling *generic types* and checking the constraints on type parameters.
    * `Comparable` directly relates to the Go language's rules for comparing values.
    * `isGeneric` is explicitly about Go generics.

6. **Create Go Code Examples:**  For the most important functions, construct simple Go code examples that demonstrate their usage and expected behavior. This helps solidify understanding and provides concrete illustrations. Think about:
    * **Typical Cases:**  Normal usage scenarios.
    * **Edge Cases:**  Situations that might be tricky or unexpected.
    * **Type Parameters:**  Demonstrate how the `all...` functions work with generics.

7. **Consider Input/Output and Assumptions:** For code examples, explicitly state the input (the type being checked) and the expected output (the boolean result). This makes the examples clearer.

8. **Look for Command-Line Arguments (Rare in This File):**  This file is about type system logic, which generally doesn't involve command-line arguments directly. Recognize this and state it.

9. **Identify Potential Pitfalls:** Think about situations where a user might misunderstand or misuse these functions. For instance:
    * Confusing `isX` and `allX` when dealing with generics.
    * Misunderstanding how `Comparable` works with custom types or interfaces.

10. **Structure the Explanation:** Organize the findings logically, grouping related functions together. Use clear headings and bullet points for readability. Start with a high-level summary and then go into more detail.

11. **Review and Refine:**  Read through the explanation to ensure accuracy, clarity, and completeness. Double-check code examples and explanations. Make sure the language is precise and avoids jargon where possible. For example, initially I might just say "checks if it's comparable" but refining it to explain *what* makes a type comparable is better.

**Self-Correction/Refinement Example During the Process:**

* **Initial Thought:** "The `isBoolean` function just checks if the type is `bool`."
* **Realization:**  Looking at the code, it uses `isBasic` and a `BasicInfo` flag. This suggests it might handle more than just the basic `bool` type. It might also include predeclared aliases or even untyped boolean constants (though the comment explicitly says it doesn't look *inside* type parameters). So, refine the explanation to reflect the use of `isBasic`.
* **Further Refinement (Generics):** When encountering `allBoolean`, the initial thought might be, "It does the same as `isBoolean`."  However, the comments and the structure with type parameters clearly indicate it's about how these predicates behave with generics. This requires a more detailed explanation and examples demonstrating the type parameter behavior.

By following these steps, and iteratively refining understanding, you can arrive at a comprehensive and accurate explanation of the code's functionality.
这段代码是 Go 语言编译器 `cmd/compile/internal/types2` 包中 `predicates.go` 文件的一部分。它的主要功能是**提供了一系列用于判断 Go 语言类型属性的谓词函数**。

这些谓词函数用于确定一个给定的 `types2.Type` 是否满足特定的条件，例如是否是基本类型、数字类型、接口类型、可比较类型等等。这些函数在编译器的类型检查、类型推断和代码生成等阶段被广泛使用。

以下是这些函数的功能列表：

* **`isValid(t Type) bool`**: 判断类型 `t` 是否有效 (非 `Invalid` 类型)。
* **`isBoolean(t Type) bool`**: 判断类型 `t` 是否是布尔类型。
* **`isInteger(t Type) bool`**: 判断类型 `t` 是否是整数类型。
* **`isUnsigned(t Type) bool`**: 判断类型 `t` 是否是无符号整数类型。
* **`isFloat(t Type) bool`**: 判断类型 `t` 是否是浮点数类型。
* **`isComplex(t Type) bool`**: 判断类型 `t` 是否是复数类型。
* **`isNumeric(t Type) bool`**: 判断类型 `t` 是否是数字类型 (整数、浮点数或复数)。
* **`isString(t Type) bool`**: 判断类型 `t` 是否是字符串类型。
* **`isIntegerOrFloat(t Type) bool`**: 判断类型 `t` 是否是整数或浮点数类型。
* **`isConstType(t Type) bool`**: 判断类型 `t` 是否是常量类型。
* **`isBasic(t Type, info BasicInfo) bool`**: 判断类型 `t` 的底层类型是否是具有指定 `BasicInfo` 的基本类型。
* **`allBoolean(t Type) bool`**:  如果 `t` 是类型参数，则当类型参数类型集中的所有类型都是布尔类型时返回 `true`。否则，等同于 `isBoolean(t)`。
* **`allInteger(t Type) bool`**:  如果 `t` 是类型参数，则当类型参数类型集中的所有类型都是整数类型时返回 `true`。否则，等同于 `isInteger(t)`。
* **`allUnsigned(t Type) bool`**: 如果 `t` 是类型参数，则当类型参数类型集中的所有类型都是无符号整数类型时返回 `true`。否则，等同于 `isUnsigned(t)`。
* **`allNumeric(t Type) bool`**:  如果 `t` 是类型参数，则当类型参数类型集中的所有类型都是数字类型时返回 `true`。否则，等同于 `isNumeric(t)`。
* **`allString(t Type) bool`**:   如果 `t` 是类型参数，则当类型参数类型集中的所有类型都是字符串类型时返回 `true`。否则，等同于 `isString(t)`。
* **`allOrdered(t Type) bool`**:   如果 `t` 是类型参数，则当类型参数类型集中的所有类型都是有序类型时返回 `true`。否则，它依赖于 `BasicInfo` 中是否包含 `IsOrdered`。
* **`allNumericOrString(t Type) bool`**: 如果 `t` 是类型参数，则当类型参数类型集中的所有类型都是数字或字符串类型时返回 `true`。否则，它依赖于 `BasicInfo` 中是否包含 `IsNumeric` 或 `IsString`。
* **`allBasic(t Type, info BasicInfo) bool`**: 如果 `t` 是类型参数，则当类型参数类型集中的所有类型都满足 `isBasic(t, info)` 时返回 `true`。否则，等同于 `isBasic(t, info)`。
* **`hasName(t Type) bool`**: 判断类型 `t` 是否有名称 (预声明类型、定义类型或类型参数)。
* **`isTypeLit(t Type) bool`**: 判断类型 `t` 是否是类型字面量 (非定义类型，包括基本类型)。
* **`isTyped(t Type) bool`**: 判断类型 `t` 是否是已定型的 (不是无类型常量或布尔值)。
* **`isUntyped(t Type) bool`**: 判断类型 `t` 是否是无类型的。
* **`isUntypedNumeric(t Type) bool`**: 判断类型 `t` 是否是无类型的数字类型。
* **`IsInterface(t Type) bool`**: 判断类型 `t` 是否是接口类型。
* **`isNonTypeParamInterface(t Type) bool`**: 判断类型 `t` 是否是接口类型但不是类型参数。
* **`isTypeParam(t Type) bool`**: 判断类型 `t` 是否是类型参数。
* **`hasEmptyTypeset(t Type) bool`**: 判断类型 `t` 是否是具有空类型集的类型参数。
* **`isGeneric(t Type) bool`**: 判断类型 `t` 是否是泛型、未实例化的类型。
* **`Comparable(T Type) bool`**: 判断类型 `T` 的值是否可比较。
* **`comparableType(T Type, dynamic bool, seen map[Type]bool, reportf func(string, ...interface{})) bool`**:  `Comparable` 的底层实现，用于判断类型是否可比较，可以指定是否考虑动态类型，并可提供报告函数。
* **`hasNil(t Type) bool`**: 判断类型 `t` 是否包含 `nil` 值。
* **`samePkg(a, b *Package) bool`**: 判断包 `a` 和 `b` 是否相同。
* **`comparer` 结构体和相关方法 (`identical`, `identicalOrigin`)**: 用于比较两个类型是否相同，可以忽略结构体标签和无效类型。
* **`identicalInstance(xorig Type, xargs []Type, yorig Type, yargs []Type) bool`**: 判断两个类型实例化是否相同。
* **`Default(t Type) Type`**: 返回无类型类型的默认定型类型。
* **`maxType(x, y Type) Type`**: 返回包含类型 `x` 和 `y` 的 "最大" 类型。
* **`clone[P *T, T any](p P) P`**: 创建指向 `p` 的 "扁平副本" 的指针。
* **`isValidName(s string) bool`**: 判断字符串 `s` 是否是有效的 Go 标识符。

**它可以推理出这是 Go 语言类型系统功能的实现，特别是关于类型检查和类型推断的部分。**

**Go 代码示例：**

假设我们有以下 Go 代码：

```go
package main

import "fmt"
import "go/types"

func main() {
	// 创建一个 types.Config 和 types.Info
	conf := types.Config{}
	info := &types.Info{
		Types: make(map[expr]types.TypeAndValue),
	}

	// 创建一个空的包
	pkg := types.NewPackage("example.com/mypkg", "mypkg")

	// 解析一些简单的表达式
	exprs := []string{"10", "3.14", "true", `"hello"`}
	for _, exprStr := range exprs {
		expr, err := parser.ParseExpr(exprStr)
		if err != nil {
			fmt.Println("Error parsing expression:", err)
			return
		}

		// 对表达式进行类型检查
		tv, err := types.CheckExpr(expr, &conf, pkg, info)
		if err != nil {
			fmt.Println("Error checking expression:", err)
			return
		}

		// 使用 predicates.go 中的函数判断类型
		fmt.Printf("Expression: %s, Type: %v\n", exprStr, tv.Type)
		fmt.Printf("  isInteger: %t\n", types.IsInteger(tv.Type))
		fmt.Printf("  isFloat: %t\n", types.IsFloat(tv.Type))
		fmt.Printf("  isString: %t\n", types.IsString(tv.Type))
		fmt.Printf("  isConstType: %t\n", types.IsConstType(tv.Type))
		fmt.Println("---")
	}

	// 示例接口类型判断
	var ifaceType *types.Interface = types.NewInterfaceType(nil, nil)
	fmt.Printf("IsInterface(%v): %t\n", ifaceType, types.IsInterface(ifaceType))

	// 示例可比较类型判断
	intType := types.Typ[types.Int]
	stringType := types.Typ[types.String]
	structType := types.NewStruct([]*types.Var{types.NewField(0, nil, "Name", stringType, false)}, nil)
	fmt.Printf("Comparable(int): %t\n", types.Comparable(intType))
	fmt.Printf("Comparable(string): %t\n", types.Comparable(stringType))
	fmt.Printf("Comparable(struct with string): %t\n", types.Comparable(structType))
}
```

**假设的输入与输出：**

在这个例子中，输入是几个简单的 Go 语言表达式的字符串。`types.CheckExpr` 函数会对这些表达式进行类型检查，而 `predicates.go` 中的函数会被用来判断检查后得到的类型。

**输出可能如下：**

```
Expression: 10, Type: int
  isInteger: true
  isFloat: false
  isString: false
  isConstType: true
---
Expression: 3.14, Type: float64
  isInteger: false
  isFloat: true
  isString: false
  isConstType: true
---
Expression: true, Type: bool
  isInteger: false
  isFloat: false
  isString: false
  isConstType: true
---
Expression: "hello", Type: string
  isInteger: false
  isFloat: false
  isString: true
  isConstType: true
---
IsInterface(&{ nil []}): true
Comparable(int): true
Comparable(string): true
Comparable(struct with string): true
```

**代码推理：**

* **`isInteger("10")`:** `types.CheckExpr` 会将字符串 "10" 推断为整数类型 `int`。`isInteger` 函数会判断这个类型是否是整数，结果为 `true`。
* **`isFloat("3.14")`:** `types.CheckExpr` 会将字符串 "3.14" 推断为浮点数类型 `float64`。`isFloat` 函数会判断这个类型是否是浮点数，结果为 `true`。
* **`isString("\"hello\"")`:** `types.CheckExpr` 会将字符串 `"hello"` 推断为字符串类型 `string`。`isString` 函数会判断这个类型是否是字符串，结果为 `true`。
* **`IsInterface(ifaceType)`:** 创建了一个新的空接口类型，`IsInterface` 函数会判断它是否是接口，结果为 `true`。
* **`Comparable(structType)`:** 创建了一个包含字符串字段的结构体类型，`Comparable` 函数会递归地检查结构体字段的类型是否可比较，因为字符串是可比较的，所以结果为 `true`。

**命令行参数：**

这段代码本身并不直接处理命令行参数。它是 Go 编译器内部类型检查逻辑的一部分。编译器本身在编译 Go 代码时会接收命令行参数，例如输入源文件路径、输出路径等，但 `predicates.go` 文件中的函数是在编译过程中被调用的，不直接参与命令行参数的解析。

**使用者易犯错的点：**

在直接使用 `go/types` 包进行类型分析时，一个常见的错误是**混淆 `isX` 和 `allX` 函数在处理泛型类型参数时的行为**。

**示例：**

```go
package main

import (
	"fmt"
	"go/types"
)

func main() {
	// 假设我们有一个类型参数 T
	tpar := types.NewTypeParam(types.NewTypeName(0, nil, "T", nil), types.NewInterfaceType([]*types.Func{}, nil))

	// 添加约束，假设 T 可以是 int 或 string
	// 注意：这里只是一个简化的模拟，实际操作更复杂
	union := types.NewUnion([]*types.Term{
		types.NewTerm(false, types.Typ[types.Int]),
		types.NewTerm(false, types.Typ[types.String]),
	})
	tpar.SetConstraint(union)

	fmt.Printf("isInteger(%v): %t\n", tpar, types.IsInteger(tpar))    // 输出: false
	fmt.Printf("allInteger(%v): %t\n", tpar, types.AllInteger(tpar))  // 输出: false
	fmt.Printf("isString(%v): %t\n", tpar, types.IsString(tpar))     // 输出: false
	fmt.Printf("allString(%v): %t\n", tpar, types.AllString(tpar))   // 输出: false
	fmt.Printf("allNumericOrString(%v): %t\n", tpar, types.AllNumericOrString(tpar)) // 输出: true
}
```

**解释：**

* `isInteger(tpar)` 返回 `false`，因为 `tpar` 本身不是一个具体的整数类型，而是一个类型参数。`isX` 系列函数对于类型参数总是返回 `false`（除非另有说明，例如 `hasName`）。
* `allInteger(tpar)` 返回 `false`，因为类型参数 `T` 的类型集中包含 `string`，不是所有类型都是整数。
* `allNumericOrString(tpar)` 返回 `true`，因为类型参数 `T` 的类型集中所有类型（`int` 和 `string`）都是数字或字符串。

**易犯错的点：**  使用者可能会错误地认为 `isInteger(tpar)` 会检查类型参数的约束中是否包含整数类型。实际上，`isX` 函数只检查给定类型本身是否符合条件，而 `allX` 函数用于检查类型参数的类型集是否都满足条件。理解这种区别对于正确处理泛型类型非常重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/predicates.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements commonly used type predicates.

package types2

import (
	"slices"
	"unicode"
)

// isValid reports whether t is a valid type.
func isValid(t Type) bool { return Unalias(t) != Typ[Invalid] }

// The isX predicates below report whether t is an X.
// If t is a type parameter the result is false; i.e.,
// these predicates don't look inside a type parameter.

func isBoolean(t Type) bool        { return isBasic(t, IsBoolean) }
func isInteger(t Type) bool        { return isBasic(t, IsInteger) }
func isUnsigned(t Type) bool       { return isBasic(t, IsUnsigned) }
func isFloat(t Type) bool          { return isBasic(t, IsFloat) }
func isComplex(t Type) bool        { return isBasic(t, IsComplex) }
func isNumeric(t Type) bool        { return isBasic(t, IsNumeric) }
func isString(t Type) bool         { return isBasic(t, IsString) }
func isIntegerOrFloat(t Type) bool { return isBasic(t, IsInteger|IsFloat) }
func isConstType(t Type) bool      { return isBasic(t, IsConstType) }

// isBasic reports whether under(t) is a basic type with the specified info.
// If t is a type parameter the result is false; i.e.,
// isBasic does not look inside a type parameter.
func isBasic(t Type, info BasicInfo) bool {
	u, _ := under(t).(*Basic)
	return u != nil && u.info&info != 0
}

// The allX predicates below report whether t is an X.
// If t is a type parameter the result is true if isX is true
// for all specified types of the type parameter's type set.
// allX is an optimized version of isX(coreType(t)) (which
// is the same as underIs(t, isX)).

func allBoolean(t Type) bool         { return allBasic(t, IsBoolean) }
func allInteger(t Type) bool         { return allBasic(t, IsInteger) }
func allUnsigned(t Type) bool        { return allBasic(t, IsUnsigned) }
func allNumeric(t Type) bool         { return allBasic(t, IsNumeric) }
func allString(t Type) bool          { return allBasic(t, IsString) }
func allOrdered(t Type) bool         { return allBasic(t, IsOrdered) }
func allNumericOrString(t Type) bool { return allBasic(t, IsNumeric|IsString) }

// allBasic reports whether under(t) is a basic type with the specified info.
// If t is a type parameter, the result is true if isBasic(t, info) is true
// for all specific types of the type parameter's type set.
// allBasic(t, info) is an optimized version of isBasic(coreType(t), info).
func allBasic(t Type, info BasicInfo) bool {
	if tpar, _ := Unalias(t).(*TypeParam); tpar != nil {
		return tpar.is(func(t *term) bool { return t != nil && isBasic(t.typ, info) })
	}
	return isBasic(t, info)
}

// hasName reports whether t has a name. This includes
// predeclared types, defined types, and type parameters.
// hasName may be called with types that are not fully set up.
func hasName(t Type) bool {
	switch Unalias(t).(type) {
	case *Basic, *Named, *TypeParam:
		return true
	}
	return false
}

// isTypeLit reports whether t is a type literal.
// This includes all non-defined types, but also basic types.
// isTypeLit may be called with types that are not fully set up.
func isTypeLit(t Type) bool {
	switch Unalias(t).(type) {
	case *Named, *TypeParam:
		return false
	}
	return true
}

// isTyped reports whether t is typed; i.e., not an untyped
// constant or boolean.
// Safe to call from types that are not fully set up.
func isTyped(t Type) bool {
	// Alias and named types cannot denote untyped types
	// so there's no need to call Unalias or under, below.
	b, _ := t.(*Basic)
	return b == nil || b.info&IsUntyped == 0
}

// isUntyped(t) is the same as !isTyped(t).
// Safe to call from types that are not fully set up.
func isUntyped(t Type) bool {
	return !isTyped(t)
}

// isUntypedNumeric reports whether t is an untyped numeric type.
// Safe to call from types that are not fully set up.
func isUntypedNumeric(t Type) bool {
	// Alias and named types cannot denote untyped types
	// so there's no need to call Unalias or under, below.
	b, _ := t.(*Basic)
	return b != nil && b.info&IsUntyped != 0 && b.info&IsNumeric != 0
}

// IsInterface reports whether t is an interface type.
func IsInterface(t Type) bool {
	_, ok := under(t).(*Interface)
	return ok
}

// isNonTypeParamInterface reports whether t is an interface type but not a type parameter.
func isNonTypeParamInterface(t Type) bool {
	return !isTypeParam(t) && IsInterface(t)
}

// isTypeParam reports whether t is a type parameter.
func isTypeParam(t Type) bool {
	_, ok := Unalias(t).(*TypeParam)
	return ok
}

// hasEmptyTypeset reports whether t is a type parameter with an empty type set.
// The function does not force the computation of the type set and so is safe to
// use anywhere, but it may report a false negative if the type set has not been
// computed yet.
func hasEmptyTypeset(t Type) bool {
	if tpar, _ := Unalias(t).(*TypeParam); tpar != nil && tpar.bound != nil {
		iface, _ := safeUnderlying(tpar.bound).(*Interface)
		return iface != nil && iface.tset != nil && iface.tset.IsEmpty()
	}
	return false
}

// isGeneric reports whether a type is a generic, uninstantiated type
// (generic signatures are not included).
// TODO(gri) should we include signatures or assert that they are not present?
func isGeneric(t Type) bool {
	// A parameterized type is only generic if it doesn't have an instantiation already.
	if alias, _ := t.(*Alias); alias != nil && alias.tparams != nil && alias.targs == nil {
		return true
	}
	named := asNamed(t)
	return named != nil && named.obj != nil && named.inst == nil && named.TypeParams().Len() > 0
}

// Comparable reports whether values of type T are comparable.
func Comparable(T Type) bool {
	return comparableType(T, true, nil, nil)
}

// If dynamic is set, non-type parameter interfaces are always comparable.
// If reportf != nil, it may be used to report why T is not comparable.
func comparableType(T Type, dynamic bool, seen map[Type]bool, reportf func(string, ...interface{})) bool {
	if seen[T] {
		return true
	}
	if seen == nil {
		seen = make(map[Type]bool)
	}
	seen[T] = true

	switch t := under(T).(type) {
	case *Basic:
		// assume invalid types to be comparable
		// to avoid follow-up errors
		return t.kind != UntypedNil
	case *Pointer, *Chan:
		return true
	case *Struct:
		for _, f := range t.fields {
			if !comparableType(f.typ, dynamic, seen, nil) {
				if reportf != nil {
					reportf("struct containing %s cannot be compared", f.typ)
				}
				return false
			}
		}
		return true
	case *Array:
		if !comparableType(t.elem, dynamic, seen, nil) {
			if reportf != nil {
				reportf("%s cannot be compared", t)
			}
			return false
		}
		return true
	case *Interface:
		if dynamic && !isTypeParam(T) || t.typeSet().IsComparable(seen) {
			return true
		}
		if reportf != nil {
			if t.typeSet().IsEmpty() {
				reportf("empty type set")
			} else {
				reportf("incomparable types in type set")
			}
		}
		// fallthrough
	}
	return false
}

// hasNil reports whether type t includes the nil value.
func hasNil(t Type) bool {
	switch u := under(t).(type) {
	case *Basic:
		return u.kind == UnsafePointer
	case *Slice, *Pointer, *Signature, *Map, *Chan:
		return true
	case *Interface:
		return !isTypeParam(t) || underIs(t, func(u Type) bool {
			return u != nil && hasNil(u)
		})
	}
	return false
}

// samePkg reports whether packages a and b are the same.
func samePkg(a, b *Package) bool {
	// package is nil for objects in universe scope
	if a == nil || b == nil {
		return a == b
	}
	// a != nil && b != nil
	return a.path == b.path
}

// An ifacePair is a node in a stack of interface type pairs compared for identity.
type ifacePair struct {
	x, y *Interface
	prev *ifacePair
}

func (p *ifacePair) identical(q *ifacePair) bool {
	return p.x == q.x && p.y == q.y || p.x == q.y && p.y == q.x
}

// A comparer is used to compare types.
type comparer struct {
	ignoreTags     bool // if set, identical ignores struct tags
	ignoreInvalids bool // if set, identical treats an invalid type as identical to any type
}

// For changes to this code the corresponding changes should be made to unifier.nify.
func (c *comparer) identical(x, y Type, p *ifacePair) bool {
	x = Unalias(x)
	y = Unalias(y)

	if x == y {
		return true
	}

	if c.ignoreInvalids && (!isValid(x) || !isValid(y)) {
		return true
	}

	switch x := x.(type) {
	case *Basic:
		// Basic types are singletons except for the rune and byte
		// aliases, thus we cannot solely rely on the x == y check
		// above. See also comment in TypeName.IsAlias.
		if y, ok := y.(*Basic); ok {
			return x.kind == y.kind
		}

	case *Array:
		// Two array types are identical if they have identical element types
		// and the same array length.
		if y, ok := y.(*Array); ok {
			// If one or both array lengths are unknown (< 0) due to some error,
			// assume they are the same to avoid spurious follow-on errors.
			return (x.len < 0 || y.len < 0 || x.len == y.len) && c.identical(x.elem, y.elem, p)
		}

	case *Slice:
		// Two slice types are identical if they have identical element types.
		if y, ok := y.(*Slice); ok {
			return c.identical(x.elem, y.elem, p)
		}

	case *Struct:
		// Two struct types are identical if they have the same sequence of fields,
		// and if corresponding fields have the same names, and identical types,
		// and identical tags. Two embedded fields are considered to have the same
		// name. Lower-case field names from different packages are always different.
		if y, ok := y.(*Struct); ok {
			if x.NumFields() == y.NumFields() {
				for i, f := range x.fields {
					g := y.fields[i]
					if f.embedded != g.embedded ||
						!c.ignoreTags && x.Tag(i) != y.Tag(i) ||
						!f.sameId(g.pkg, g.name, false) ||
						!c.identical(f.typ, g.typ, p) {
						return false
					}
				}
				return true
			}
		}

	case *Pointer:
		// Two pointer types are identical if they have identical base types.
		if y, ok := y.(*Pointer); ok {
			return c.identical(x.base, y.base, p)
		}

	case *Tuple:
		// Two tuples types are identical if they have the same number of elements
		// and corresponding elements have identical types.
		if y, ok := y.(*Tuple); ok {
			if x.Len() == y.Len() {
				if x != nil {
					for i, v := range x.vars {
						w := y.vars[i]
						if !c.identical(v.typ, w.typ, p) {
							return false
						}
					}
				}
				return true
			}
		}

	case *Signature:
		y, _ := y.(*Signature)
		if y == nil {
			return false
		}

		// Two function types are identical if they have the same number of
		// parameters and result values, corresponding parameter and result types
		// are identical, and either both functions are variadic or neither is.
		// Parameter and result names are not required to match, and type
		// parameters are considered identical modulo renaming.

		if x.TypeParams().Len() != y.TypeParams().Len() {
			return false
		}

		// In the case of generic signatures, we will substitute in yparams and
		// yresults.
		yparams := y.params
		yresults := y.results

		if x.TypeParams().Len() > 0 {
			// We must ignore type parameter names when comparing x and y. The
			// easiest way to do this is to substitute x's type parameters for y's.
			xtparams := x.TypeParams().list()
			ytparams := y.TypeParams().list()

			var targs []Type
			for i := range xtparams {
				targs = append(targs, x.TypeParams().At(i))
			}
			smap := makeSubstMap(ytparams, targs)

			var check *Checker   // ok to call subst on a nil *Checker
			ctxt := NewContext() // need a non-nil Context for the substitution below

			// Constraints must be pair-wise identical, after substitution.
			for i, xtparam := range xtparams {
				ybound := check.subst(nopos, ytparams[i].bound, smap, nil, ctxt)
				if !c.identical(xtparam.bound, ybound, p) {
					return false
				}
			}

			yparams = check.subst(nopos, y.params, smap, nil, ctxt).(*Tuple)
			yresults = check.subst(nopos, y.results, smap, nil, ctxt).(*Tuple)
		}

		return x.variadic == y.variadic &&
			c.identical(x.params, yparams, p) &&
			c.identical(x.results, yresults, p)

	case *Union:
		if y, _ := y.(*Union); y != nil {
			// TODO(rfindley): can this be reached during type checking? If so,
			// consider passing a type set map.
			unionSets := make(map[*Union]*_TypeSet)
			xset := computeUnionTypeSet(nil, unionSets, nopos, x)
			yset := computeUnionTypeSet(nil, unionSets, nopos, y)
			return xset.terms.equal(yset.terms)
		}

	case *Interface:
		// Two interface types are identical if they describe the same type sets.
		// With the existing implementation restriction, this simplifies to:
		//
		// Two interface types are identical if they have the same set of methods with
		// the same names and identical function types, and if any type restrictions
		// are the same. Lower-case method names from different packages are always
		// different. The order of the methods is irrelevant.
		if y, ok := y.(*Interface); ok {
			xset := x.typeSet()
			yset := y.typeSet()
			if xset.comparable != yset.comparable {
				return false
			}
			if !xset.terms.equal(yset.terms) {
				return false
			}
			a := xset.methods
			b := yset.methods
			if len(a) == len(b) {
				// Interface types are the only types where cycles can occur
				// that are not "terminated" via named types; and such cycles
				// can only be created via method parameter types that are
				// anonymous interfaces (directly or indirectly) embedding
				// the current interface. Example:
				//
				//    type T interface {
				//        m() interface{T}
				//    }
				//
				// If two such (differently named) interfaces are compared,
				// endless recursion occurs if the cycle is not detected.
				//
				// If x and y were compared before, they must be equal
				// (if they were not, the recursion would have stopped);
				// search the ifacePair stack for the same pair.
				//
				// This is a quadratic algorithm, but in practice these stacks
				// are extremely short (bounded by the nesting depth of interface
				// type declarations that recur via parameter types, an extremely
				// rare occurrence). An alternative implementation might use a
				// "visited" map, but that is probably less efficient overall.
				q := &ifacePair{x, y, p}
				for p != nil {
					if p.identical(q) {
						return true // same pair was compared before
					}
					p = p.prev
				}
				if debug {
					assertSortedMethods(a)
					assertSortedMethods(b)
				}
				for i, f := range a {
					g := b[i]
					if f.Id() != g.Id() || !c.identical(f.typ, g.typ, q) {
						return false
					}
				}
				return true
			}
		}

	case *Map:
		// Two map types are identical if they have identical key and value types.
		if y, ok := y.(*Map); ok {
			return c.identical(x.key, y.key, p) && c.identical(x.elem, y.elem, p)
		}

	case *Chan:
		// Two channel types are identical if they have identical value types
		// and the same direction.
		if y, ok := y.(*Chan); ok {
			return x.dir == y.dir && c.identical(x.elem, y.elem, p)
		}

	case *Named:
		// Two named types are identical if their type names originate
		// in the same type declaration; if they are instantiated they
		// must have identical type argument lists.
		if y := asNamed(y); y != nil {
			// check type arguments before origins to match unifier
			// (for correct source code we need to do all checks so
			// order doesn't matter)
			xargs := x.TypeArgs().list()
			yargs := y.TypeArgs().list()
			if len(xargs) != len(yargs) {
				return false
			}
			for i, xarg := range xargs {
				if !Identical(xarg, yargs[i]) {
					return false
				}
			}
			return identicalOrigin(x, y)
		}

	case *TypeParam:
		// nothing to do (x and y being equal is caught in the very beginning of this function)

	case nil:
		// avoid a crash in case of nil type

	default:
		panic("unreachable")
	}

	return false
}

// identicalOrigin reports whether x and y originated in the same declaration.
func identicalOrigin(x, y *Named) bool {
	// TODO(gri) is this correct?
	return x.Origin().obj == y.Origin().obj
}

// identicalInstance reports if two type instantiations are identical.
// Instantiations are identical if their origin and type arguments are
// identical.
func identicalInstance(xorig Type, xargs []Type, yorig Type, yargs []Type) bool {
	if !slices.EqualFunc(xargs, yargs, Identical) {
		return false
	}

	return Identical(xorig, yorig)
}

// Default returns the default "typed" type for an "untyped" type;
// it returns the incoming type for all other types. The default type
// for untyped nil is untyped nil.
func Default(t Type) Type {
	// Alias and named types cannot denote untyped types
	// so there's no need to call Unalias or under, below.
	if t, _ := t.(*Basic); t != nil {
		switch t.kind {
		case UntypedBool:
			return Typ[Bool]
		case UntypedInt:
			return Typ[Int]
		case UntypedRune:
			return universeRune // use 'rune' name
		case UntypedFloat:
			return Typ[Float64]
		case UntypedComplex:
			return Typ[Complex128]
		case UntypedString:
			return Typ[String]
		}
	}
	return t
}

// maxType returns the "largest" type that encompasses both x and y.
// If x and y are different untyped numeric types, the result is the type of x or y
// that appears later in this list: integer, rune, floating-point, complex.
// Otherwise, if x != y, the result is nil.
func maxType(x, y Type) Type {
	// We only care about untyped types (for now), so == is good enough.
	// TODO(gri) investigate generalizing this function to simplify code elsewhere
	if x == y {
		return x
	}
	if isUntypedNumeric(x) && isUntypedNumeric(y) {
		// untyped types are basic types
		if x.(*Basic).kind > y.(*Basic).kind {
			return x
		}
		return y
	}
	return nil
}

// clone makes a "flat copy" of *p and returns a pointer to the copy.
func clone[P *T, T any](p P) P {
	c := *p
	return &c
}

// isValidName reports whether s is a valid Go identifier.
func isValidName(s string) bool {
	for i, ch := range s {
		if !(unicode.IsLetter(ch) || ch == '_' || i > 0 && unicode.IsDigit(ch)) {
			return false
		}
	}
	return true
}
```