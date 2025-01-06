Response: Let's break down the thought process for analyzing this Go code and fulfilling the request.

**1. Initial Understanding: Core Functionality**

The first step is to read the code and identify its primary purpose. The package name `types2` and the file name `decl.go` immediately suggest it's related to handling declarations within the Go type checker. Keywords like `declare`, `objDecl`, `constDecl`, `varDecl`, and `typeDecl` reinforce this. The comments about "colors" (white, grey, black) hint at a mechanism for tracking the state of type inference, particularly in the context of potential cycles.

**2. Dissecting Key Functions:**

* **`declare`:**  This looks like a straightforward function for inserting an object into a scope and recording its definition. The blank identifier check is a clear Go language feature being handled.
* **`objDecl`:** This seems to be the central dispatch point for processing declarations. The comments about colors and the object path strongly suggest it's handling the complexities of type inference, including cycle detection. The tracing (`check.conf.Trace`) is a common debugging technique and can be noted.
* **`constDecl`, `varDecl`, `typeDecl`, `funcDecl`:** These seem like specialized handlers for different kinds of declarations. The presence of parameters like `syntax.Expr` and `syntax.TypeDecl` indicates interaction with the Go syntax tree.
* **`validCycle`, `cycleError`, `firstInSrc`:** These functions clearly deal with the detection and reporting of declaration cycles, a crucial part of ensuring type safety in Go.
* **`collectTypeParams`, `bound`, `declareTypeParam`:** These seem related to the handling of type parameters (generics), a relatively newer feature in Go.

**3. Identifying Go Language Features Implemented:**

Based on the function names and code structure, I can infer the following Go language features are being implemented:

* **Variable Declarations:** `varDecl` obviously handles these.
* **Constant Declarations:** `constDecl` is responsible for this.
* **Type Declarations (including aliases):** `typeDecl` manages both regular type definitions and type aliases. The checks for `tdecl.Alias` and the version checks (`go1_9`, `go1_18`, `go1_23`) are strong indicators.
* **Function Declarations:** `funcDecl` is responsible for processing function signatures and bodies.
* **Generics (Type Parameters):**  The presence of `TParamList`, `collectTypeParams`, `TypeParam`, and version checks for Go 1.18 and 1.23 point directly to generics support.
* **Declaration Cycles:**  The `validCycle` and `cycleError` functions, along with the color-based tracking in `objDecl`, are the mechanisms for detecting and reporting invalid recursive declarations.
* **Blank Identifier:** The explicit check in `declare` for `obj.Name() != "_"` confirms this.
* **Method Declarations:** While not a dedicated function, `collectMethods` handles the association of methods with types.
* **`iota`:** The handling of `iota` within `constDecl` is evident.

**4. Code Example Construction (Trial and Error/Refinement):**

For each identified feature, construct a simple Go code example that demonstrates its usage. For more complex features like generics and cycles, multiple examples might be needed to illustrate different aspects.

* **Initial thought for generics:**  A simple generic function or type.
* **Refinement for generics:**  Show both a generic type and a generic function to cover more ground. Include a constraint to demonstrate that aspect.
* **Initial thought for cycles:** A direct self-referential type.
* **Refinement for cycles:**  Show both a simple type cycle and a cycle involving a constant or variable, as the code handles these differently.

**5. Input/Output for Code Reasoning:**

For the cycle detection logic, specifically `validCycle` and `cycleError`, it's helpful to create a hypothetical scenario.

* **Input:** Imagine a sequence of declarations that form a cycle (e.g., `type A B`, `type B A`).
* **Process:**  Walk through how the `objDecl` function would color the objects, how `validCycle` would traverse the `objPath`, and how `cycleError` would format the error message.
* **Output:**  Predict the error message the compiler would generate.

**6. Command-Line Parameters:**

Scan the code for any references to configuration or flags that might be controlled by command-line arguments. The `check.conf.Trace` and the version checks (`go1_9`, `go1_18`, `go1_23`) are good candidates. Research the standard Go compiler flags (like `-lang` and experiment flags) to understand how these configurations are typically set.

**7. Common Mistakes:**

Think about common errors developers make when using these Go features.

* **Cycles:**  Accidental or overly complex recursive type definitions are a classic mistake.
* **Generics:** Misunderstanding type constraints or using type parameters in invalid contexts.
* **`iota`:**  Incorrectly assuming `iota`'s value outside of a `const` block or within different `const` blocks.

**8. Structuring the Answer:**

Organize the findings into clear sections as requested: functionality list, feature explanation with code examples, code reasoning, command-line parameters, and common mistakes. Use code blocks for examples and format the output clearly.

**Self-Correction/Refinement During the Process:**

* **Initial Interpretation:** I might initially focus too much on low-level details. It's important to step back and identify the high-level Go language features being implemented.
* **Code Examples:** My initial examples might be too simplistic. I need to ensure they accurately demonstrate the specific aspects of the feature being discussed.
* **Command-Line Parameters:**  I might initially miss some implicit dependencies on compiler flags. Researching the related Go compiler documentation is crucial here.
* **Common Mistakes:** I should think from the perspective of a Go developer encountering errors related to declarations. What are the typical pitfalls?

By following this systematic approach of understanding, dissecting, inferring, illustrating, and considering potential issues, I can generate a comprehensive and accurate answer to the request.
`go/src/cmd/compile/internal/types2/decl.go` 这个文件是 Go 语言编译器 `types2` 包的一部分，主要负责处理 Go 语言中各种声明语句的类型检查和对象绑定。 它的功能可以概括为以下几个方面：

1. **声明对象的符号表管理和作用域控制:**
   - `declare` 函数负责将声明的对象插入到当前作用域 (`Scope`) 中，并检查是否存在重复声明。
   - 它处理了空白标识符 `_` 的特殊情况，空白标识符不引入新的绑定。
   - 它记录了标识符 (`syntax.Name`) 到对应对象 (`Object`) 的定义。

2. **对象声明的类型检查 (`objDecl`):**
   - 这是类型检查的核心函数，负责根据对象的类型（常量、变量、类型、函数）调用相应的类型检查函数。
   - 它使用颜色标记 (`white`, `grey`, `black`) 来跟踪对象类型推断的状态，并用于检测循环依赖。
   - 它维护一个对象路径 (`objPath`) 栈，用于检测和报告声明循环。

3. **常量声明的类型检查 (`constDecl`):**
   - 负责检查常量声明的类型和初始化表达式。
   - 它处理了 `iota` 的值，`iota` 在常量声明块中递增。
   - 它检查常量类型是否有效。
   - 它评估常量初始化表达式，并将结果赋值给常量对象。

4. **变量声明的类型检查 (`varDecl`):**
   - 负责检查变量声明的类型和初始化表达式。
   - 它处理了多变量同时赋值的情况。
   - 如果没有显式类型，它会尝试从初始化表达式中推断变量类型。

5. **类型声明的类型检查 (`typeDecl`):**
   - 负责检查类型声明，包括类型别名和新类型定义。
   - 它处理了泛型类型声明，包括收集类型参数。
   - 它检查类型别名是否符合 Go 版本要求。
   - 它检测并报告无效的递归类型定义。

6. **函数声明的类型检查 (`funcDecl`):**
   - 负责检查函数声明，包括函数签名和函数体。
   - 它处理了泛型函数声明。
   - 它将函数体放入延迟处理队列，以便在所有全局声明处理完毕后再进行类型检查。

7. **处理类型参数 (`collectTypeParams`, `declareTypeParam`, `bound`):**
   - `collectTypeParams` 负责收集类型参数列表，并将它们绑定到类型或函数。
   - `declareTypeParam` 声明单个类型参数。
   - `bound` 函数处理类型参数的约束。

8. **检测和报告声明循环 (`validCycle`, `cycleError`, `firstInSrc`):**
   - `validCycle` 函数检查是否存在有效的声明循环。
   - `cycleError` 函数报告检测到的声明循环。
   - `firstInSrc` 函数找到循环中源代码位置最靠前的对象，用于错误报告。

9. **方法收集 (`collectMethods`):**
   - 负责收集与类型关联的方法。
   - 它检查方法名是否与类型中的字段名冲突。
   - 它检查同一类型中方法名是否重复。

10. **处理块内的声明语句 (`declStmt`):**
    - `declStmt` 函数负责处理函数或代码块内的常量、变量和类型声明语句。
    - 它管理 `iota` 的上下文。
    - 它处理常量和变量的初始化。
    - 它控制局部变量和类型的生命周期和作用域。

**它是什么Go语言功能的实现？**

这个文件是 Go 语言编译器中 **类型检查器** 的核心组成部分，负责实现以下 Go 语言功能相关的类型检查：

- **变量声明:**  `var x int`, `y := 10` 等。
- **常量声明:** `const PI = 3.14`, `const ( A = 1; B )` 等，以及 `iota` 的使用。
- **类型声明:** `type MyInt int`, `type Alias = int`，以及泛型类型声明 `type Vector[T any] []T`。
- **函数声明:** `func add(a, b int) int { ... }`, 以及泛型函数声明 `func Print[T any](s []T) { ... }`。
- **方法声明:**  与特定类型关联的函数，如 `func (r Rectangle) Area() int { ... }`。
- **类型参数 (Generics):**  对泛型类型和函数的类型参数进行声明和约束检查。
- **作用域规则:** 确保变量、常量、类型和函数在正确的范围内被声明和使用。
- **声明循环检测:**  防止由于类型或值的相互依赖导致的无限循环。

**Go 代码举例说明:**

```go
package main

// 变量声明
var globalVar int = 10

func main() {
	// 局部变量声明，类型推断
	localVar := "hello"

	// 常量声明
	const constVal = 100

	// 多个常量声明，iota 的使用
	const (
		EnumValue1 = iota // 0
		EnumValue2         // 1
		EnumValue3         // 2
	)

	// 类型声明
	type MyString string

	// 类型别名 (Go 1.9+)
	type Text = string

	// 泛型类型声明 (Go 1.18+)
	type List[T any] []T

	// 泛型函数声明 (Go 1.18+)
	func Print[T any](s []T) {
		// ...
	}

	// 函数声明
	func add(a, b int) int {
		return a + b
	}

	// 方法声明
	type Rectangle struct {
		Width  int
		Height int
	}
	func (r Rectangle) Area() int {
		return r.Width * r.Height
	}

	_ = localVar
	_ = constVal
	_ = EnumValue1
	_ = MyString("world")
	_ = Text("example")
	_ = List[int]{1, 2, 3}
	Print([]string{"a", "b"})
	_ = add(1, 2)
	rect := Rectangle{Width: 5, Height: 10}
	_ = rect.Area()
}

// 声明循环 - 编译器会报错
// type A B
// type B A

// const (
// 	C = D
// 	D = C
// )
```

**假设的输入与输出 (代码推理):**

假设有以下代码片段作为输入：

```go
package main

type A struct {
	b *B
}

type B struct {
	a *A
}
```

**推断过程:**

1. **`objDecl` 处理 `A` 的声明:**
   - `A` 的类型是 `TypeName`，颜色标记为 `white`。
   - 调用 `typeDecl` 处理类型声明 `type A struct { b *B }`。
   - 在 `typeDecl` 中，遇到字段 `b *B`，需要解析类型 `*B`。
   - 此时 `B` 的类型尚未确定，颜色为 `white`。
   - `objDecl` 被递归调用来处理 `B` 的声明。

2. **`objDecl` 处理 `B` 的声明:**
   - `B` 的类型是 `TypeName`，颜色标记为 `white`。
   - 调用 `typeDecl` 处理类型声明 `type B struct { a *A }`。
   - 在 `typeDecl` 中，遇到字段 `a *A`，需要解析类型 `*A`。
   - 此时 `A` 的类型正在处理中，颜色标记为 `grey` (因为已经进入 `objDecl` 但尚未完成)。

3. **检测到循环:**
   - 在处理 `B` 的字段 `a *A` 时，发现 `A` 的颜色是 `grey`，表示正在进行类型推断，并且在当前的 `objPath` 上，从而检测到循环依赖。

**输出 (预期编译器错误):**

```
./main.go:3:2: invalid recursive type A refers to itself
./main.go:7:2: invalid recursive type B refers to itself
```

**命令行参数的具体处理:**

该文件本身的代码并没有直接处理命令行参数。命令行参数的处理通常发生在 `cmd/compile/internal/gc` 包或者更上层的编译器驱动程序中。

然而，`types2` 包的类型检查行为会受到一些全局配置的影响，这些配置可能由命令行参数间接控制，例如：

- **`-lang` 标志:**  用于指定 Go 语言版本。这会影响某些语法特性的支持，例如类型别名和泛型。`typeDecl` 函数中对 `go1_9` 和 `go1_18` 的检查就反映了这一点。
- **`-G` 标志 (与泛型相关):** 用于控制泛型的编译行为，可能会影响类型参数的处理。
- **`-d` 标志 (debug 选项):**  可能启用 `check.conf.Trace`，从而输出更详细的类型检查信息。
- **`-buildvcs` 标志:**  可能影响版本信息的处理。
- **实验性标志:**  例如，与类型别名参数相关的实验性标志。

**使用者易犯错的点 (基于代码推理):**

1. **声明循环:**  如上面的例子所示，在类型定义或常量/变量初始化中引入循环依赖是常见的错误。`types2/decl.go` 中的颜色标记和循环检测机制旨在捕获这类错误。

   ```go
   // 错误示例
   type X Y
   type Y X

   const a = b + 1
   const b = a + 1
   ```

2. **在函数内部错误地使用 `iota`:** `iota` 的值在 `const` 声明块中隐式递增，如果在函数内部错误地使用 `iota` 或在不相关的 `const` 块中使用，可能会得到意想不到的结果。

   ```go
   package main

   func main() {
       const x = iota // 错误：iota 只能在常量声明中使用

       const (
           a = iota // 0
       )

       println(a) // 输出 0
   }
   ```

3. **对类型别名的理解不足:**  类型别名只是给现有类型起了另一个名字，它们在类型检查时是完全等价的。 容易混淆类型别名和新类型定义。

   ```go
   package main

   type MyInt = int
   type NewInt int

   func main() {
       var a MyInt = 10
       var b int = a // 正确：MyInt 和 int 是同一个类型

       var c NewInt = 20
       // var d int = c // 错误：NewInt 和 int 是不同的类型
       var d int = int(c) // 需要显式类型转换
       println(b, d)
   }
   ```

4. **泛型类型参数的约束错误:**  在使用泛型时，如果类型参数的约束不满足，编译器会报错。

   ```go
   package main

   type Numeric interface {
       int | float64
   }

   func Add[T Numeric](a, b T) T {
       return a + b
   }

   func main() {
       println(Add(1, 2))     // 正确
       println(Add(1.5, 2.5)) // 正确
       // println(Add("hello", "world")) // 错误：string 不满足 Numeric 约束
   }
   ```

总而言之，`go/src/cmd/compile/internal/types2/decl.go` 是 Go 语言编译器类型检查的核心模块之一，它细致地处理了各种声明语句，并确保代码的类型安全性和符合 Go 语言的规范。 理解它的功能有助于深入理解 Go 语言的类型系统和编译过程。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/types2/decl.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types2

import (
	"cmd/compile/internal/syntax"
	"fmt"
	"go/constant"
	"internal/buildcfg"
	. "internal/types/errors"
	"slices"
)

func (check *Checker) declare(scope *Scope, id *syntax.Name, obj Object, pos syntax.Pos) {
	// spec: "The blank identifier, represented by the underscore
	// character _, may be used in a declaration like any other
	// identifier but the declaration does not introduce a new
	// binding."
	if obj.Name() != "_" {
		if alt := scope.Insert(obj); alt != nil {
			err := check.newError(DuplicateDecl)
			err.addf(obj, "%s redeclared in this block", obj.Name())
			err.addAltDecl(alt)
			err.report()
			return
		}
		obj.setScopePos(pos)
	}
	if id != nil {
		check.recordDef(id, obj)
	}
}

// pathString returns a string of the form a->b-> ... ->g for a path [a, b, ... g].
func pathString(path []Object) string {
	var s string
	for i, p := range path {
		if i > 0 {
			s += "->"
		}
		s += p.Name()
	}
	return s
}

// objDecl type-checks the declaration of obj in its respective (file) environment.
// For the meaning of def, see Checker.definedType, in typexpr.go.
func (check *Checker) objDecl(obj Object, def *TypeName) {
	if check.conf.Trace && obj.Type() == nil {
		if check.indent == 0 {
			fmt.Println() // empty line between top-level objects for readability
		}
		check.trace(obj.Pos(), "-- checking %s (%s, objPath = %s)", obj, obj.color(), pathString(check.objPath))
		check.indent++
		defer func() {
			check.indent--
			check.trace(obj.Pos(), "=> %s (%s)", obj, obj.color())
		}()
	}

	// Checking the declaration of obj means inferring its type
	// (and possibly its value, for constants).
	// An object's type (and thus the object) may be in one of
	// three states which are expressed by colors:
	//
	// - an object whose type is not yet known is painted white (initial color)
	// - an object whose type is in the process of being inferred is painted grey
	// - an object whose type is fully inferred is painted black
	//
	// During type inference, an object's color changes from white to grey
	// to black (pre-declared objects are painted black from the start).
	// A black object (i.e., its type) can only depend on (refer to) other black
	// ones. White and grey objects may depend on white and black objects.
	// A dependency on a grey object indicates a cycle which may or may not be
	// valid.
	//
	// When objects turn grey, they are pushed on the object path (a stack);
	// they are popped again when they turn black. Thus, if a grey object (a
	// cycle) is encountered, it is on the object path, and all the objects
	// it depends on are the remaining objects on that path. Color encoding
	// is such that the color value of a grey object indicates the index of
	// that object in the object path.

	// During type-checking, white objects may be assigned a type without
	// traversing through objDecl; e.g., when initializing constants and
	// variables. Update the colors of those objects here (rather than
	// everywhere where we set the type) to satisfy the color invariants.
	if obj.color() == white && obj.Type() != nil {
		obj.setColor(black)
		return
	}

	switch obj.color() {
	case white:
		assert(obj.Type() == nil)
		// All color values other than white and black are considered grey.
		// Because black and white are < grey, all values >= grey are grey.
		// Use those values to encode the object's index into the object path.
		obj.setColor(grey + color(check.push(obj)))
		defer func() {
			check.pop().setColor(black)
		}()

	case black:
		assert(obj.Type() != nil)
		return

	default:
		// Color values other than white or black are considered grey.
		fallthrough

	case grey:
		// We have a (possibly invalid) cycle.
		// In the existing code, this is marked by a non-nil type
		// for the object except for constants and variables whose
		// type may be non-nil (known), or nil if it depends on the
		// not-yet known initialization value.
		// In the former case, set the type to Typ[Invalid] because
		// we have an initialization cycle. The cycle error will be
		// reported later, when determining initialization order.
		// TODO(gri) Report cycle here and simplify initialization
		// order code.
		switch obj := obj.(type) {
		case *Const:
			if !check.validCycle(obj) || obj.typ == nil {
				obj.typ = Typ[Invalid]
			}

		case *Var:
			if !check.validCycle(obj) || obj.typ == nil {
				obj.typ = Typ[Invalid]
			}

		case *TypeName:
			if !check.validCycle(obj) {
				// break cycle
				// (without this, calling underlying()
				// below may lead to an endless loop
				// if we have a cycle for a defined
				// (*Named) type)
				obj.typ = Typ[Invalid]
			}

		case *Func:
			if !check.validCycle(obj) {
				// Don't set obj.typ to Typ[Invalid] here
				// because plenty of code type-asserts that
				// functions have a *Signature type. Grey
				// functions have their type set to an empty
				// signature which makes it impossible to
				// initialize a variable with the function.
			}

		default:
			panic("unreachable")
		}
		assert(obj.Type() != nil)
		return
	}

	d := check.objMap[obj]
	if d == nil {
		check.dump("%v: %s should have been declared", obj.Pos(), obj)
		panic("unreachable")
	}

	// save/restore current environment and set up object environment
	defer func(env environment) {
		check.environment = env
	}(check.environment)
	check.environment = environment{scope: d.file, version: d.version}

	// Const and var declarations must not have initialization
	// cycles. We track them by remembering the current declaration
	// in check.decl. Initialization expressions depending on other
	// consts, vars, or functions, add dependencies to the current
	// check.decl.
	switch obj := obj.(type) {
	case *Const:
		check.decl = d // new package-level const decl
		check.constDecl(obj, d.vtyp, d.init, d.inherited)
	case *Var:
		check.decl = d // new package-level var decl
		check.varDecl(obj, d.lhs, d.vtyp, d.init)
	case *TypeName:
		// invalid recursive types are detected via path
		check.typeDecl(obj, d.tdecl, def)
		check.collectMethods(obj) // methods can only be added to top-level types
	case *Func:
		// functions may be recursive - no need to track dependencies
		check.funcDecl(obj, d)
	default:
		panic("unreachable")
	}
}

// validCycle reports whether the cycle starting with obj is valid and
// reports an error if it is not.
func (check *Checker) validCycle(obj Object) (valid bool) {
	// The object map contains the package scope objects and the non-interface methods.
	if debug {
		info := check.objMap[obj]
		inObjMap := info != nil && (info.fdecl == nil || info.fdecl.Recv == nil) // exclude methods
		isPkgObj := obj.Parent() == check.pkg.scope
		if isPkgObj != inObjMap {
			check.dump("%v: inconsistent object map for %s (isPkgObj = %v, inObjMap = %v)", obj.Pos(), obj, isPkgObj, inObjMap)
			panic("unreachable")
		}
	}

	// Count cycle objects.
	assert(obj.color() >= grey)
	start := obj.color() - grey // index of obj in objPath
	cycle := check.objPath[start:]
	tparCycle := false // if set, the cycle is through a type parameter list
	nval := 0          // number of (constant or variable) values in the cycle; valid if !generic
	ndef := 0          // number of type definitions in the cycle; valid if !generic
loop:
	for _, obj := range cycle {
		switch obj := obj.(type) {
		case *Const, *Var:
			nval++
		case *TypeName:
			// If we reach a generic type that is part of a cycle
			// and we are in a type parameter list, we have a cycle
			// through a type parameter list, which is invalid.
			if check.inTParamList && isGeneric(obj.typ) {
				tparCycle = true
				break loop
			}

			// Determine if the type name is an alias or not. For
			// package-level objects, use the object map which
			// provides syntactic information (which doesn't rely
			// on the order in which the objects are set up). For
			// local objects, we can rely on the order, so use
			// the object's predicate.
			// TODO(gri) It would be less fragile to always access
			// the syntactic information. We should consider storing
			// this information explicitly in the object.
			var alias bool
			if check.conf.EnableAlias {
				alias = obj.IsAlias()
			} else {
				if d := check.objMap[obj]; d != nil {
					alias = d.tdecl.Alias // package-level object
				} else {
					alias = obj.IsAlias() // function local object
				}
			}
			if !alias {
				ndef++
			}
		case *Func:
			// ignored for now
		default:
			panic("unreachable")
		}
	}

	if check.conf.Trace {
		check.trace(obj.Pos(), "## cycle detected: objPath = %s->%s (len = %d)", pathString(cycle), obj.Name(), len(cycle))
		if tparCycle {
			check.trace(obj.Pos(), "## cycle contains: generic type in a type parameter list")
		} else {
			check.trace(obj.Pos(), "## cycle contains: %d values, %d type definitions", nval, ndef)
		}
		defer func() {
			if valid {
				check.trace(obj.Pos(), "=> cycle is valid")
			} else {
				check.trace(obj.Pos(), "=> error: cycle is invalid")
			}
		}()
	}

	if !tparCycle {
		// A cycle involving only constants and variables is invalid but we
		// ignore them here because they are reported via the initialization
		// cycle check.
		if nval == len(cycle) {
			return true
		}

		// A cycle involving only types (and possibly functions) must have at least
		// one type definition to be permitted: If there is no type definition, we
		// have a sequence of alias type names which will expand ad infinitum.
		if nval == 0 && ndef > 0 {
			return true
		}
	}

	check.cycleError(cycle, firstInSrc(cycle))
	return false
}

// cycleError reports a declaration cycle starting with the object at cycle[start].
func (check *Checker) cycleError(cycle []Object, start int) {
	// name returns the (possibly qualified) object name.
	// This is needed because with generic types, cycles
	// may refer to imported types. See go.dev/issue/50788.
	// TODO(gri) This functionality is used elsewhere. Factor it out.
	name := func(obj Object) string {
		return packagePrefix(obj.Pkg(), check.qualifier) + obj.Name()
	}

	// If obj is a type alias, mark it as valid (not broken) in order to avoid follow-on errors.
	obj := cycle[start]
	tname, _ := obj.(*TypeName)
	if tname != nil && tname.IsAlias() {
		// If we use Alias nodes, it is initialized with Typ[Invalid].
		// TODO(gri) Adjust this code if we initialize with nil.
		if !check.conf.EnableAlias {
			check.validAlias(tname, Typ[Invalid])
		}
	}

	// report a more concise error for self references
	if len(cycle) == 1 {
		if tname != nil {
			check.errorf(obj, InvalidDeclCycle, "invalid recursive type: %s refers to itself", name(obj))
		} else {
			check.errorf(obj, InvalidDeclCycle, "invalid cycle in declaration: %s refers to itself", name(obj))
		}
		return
	}

	err := check.newError(InvalidDeclCycle)
	if tname != nil {
		err.addf(obj, "invalid recursive type %s", name(obj))
	} else {
		err.addf(obj, "invalid cycle in declaration of %s", name(obj))
	}
	// "cycle[i] refers to cycle[j]" for (i,j) = (s,s+1), (s+1,s+2), ..., (n-1,0), (0,1), ..., (s-1,s) for len(cycle) = n, s = start.
	for i := range cycle {
		next := cycle[(start+i+1)%len(cycle)]
		err.addf(obj, "%s refers to %s", name(obj), name(next))
		obj = next
	}
	err.report()
}

// firstInSrc reports the index of the object with the "smallest"
// source position in path. path must not be empty.
func firstInSrc(path []Object) int {
	fst, pos := 0, path[0].Pos()
	for i, t := range path[1:] {
		if cmpPos(t.Pos(), pos) < 0 {
			fst, pos = i+1, t.Pos()
		}
	}
	return fst
}

func (check *Checker) constDecl(obj *Const, typ, init syntax.Expr, inherited bool) {
	assert(obj.typ == nil)

	// use the correct value of iota and errpos
	defer func(iota constant.Value, errpos syntax.Pos) {
		check.iota = iota
		check.errpos = errpos
	}(check.iota, check.errpos)
	check.iota = obj.val
	check.errpos = nopos

	// provide valid constant value under all circumstances
	obj.val = constant.MakeUnknown()

	// determine type, if any
	if typ != nil {
		t := check.typ(typ)
		if !isConstType(t) {
			// don't report an error if the type is an invalid C (defined) type
			// (go.dev/issue/22090)
			if isValid(under(t)) {
				check.errorf(typ, InvalidConstType, "invalid constant type %s", t)
			}
			obj.typ = Typ[Invalid]
			return
		}
		obj.typ = t
	}

	// check initialization
	var x operand
	if init != nil {
		if inherited {
			// The initialization expression is inherited from a previous
			// constant declaration, and (error) positions refer to that
			// expression and not the current constant declaration. Use
			// the constant identifier position for any errors during
			// init expression evaluation since that is all we have
			// (see issues go.dev/issue/42991, go.dev/issue/42992).
			check.errpos = obj.pos
		}
		check.expr(nil, &x, init)
	}
	check.initConst(obj, &x)
}

func (check *Checker) varDecl(obj *Var, lhs []*Var, typ, init syntax.Expr) {
	assert(obj.typ == nil)

	// determine type, if any
	if typ != nil {
		obj.typ = check.varType(typ)
		// We cannot spread the type to all lhs variables if there
		// are more than one since that would mark them as checked
		// (see Checker.objDecl) and the assignment of init exprs,
		// if any, would not be checked.
		//
		// TODO(gri) If we have no init expr, we should distribute
		// a given type otherwise we need to re-evaluate the type
		// expr for each lhs variable, leading to duplicate work.
	}

	// check initialization
	if init == nil {
		if typ == nil {
			// error reported before by arityMatch
			obj.typ = Typ[Invalid]
		}
		return
	}

	if lhs == nil || len(lhs) == 1 {
		assert(lhs == nil || lhs[0] == obj)
		var x operand
		check.expr(newTarget(obj.typ, obj.name), &x, init)
		check.initVar(obj, &x, "variable declaration")
		return
	}

	if debug {
		// obj must be one of lhs
		if !slices.Contains(lhs, obj) {
			panic("inconsistent lhs")
		}
	}

	// We have multiple variables on the lhs and one init expr.
	// Make sure all variables have been given the same type if
	// one was specified, otherwise they assume the type of the
	// init expression values (was go.dev/issue/15755).
	if typ != nil {
		for _, lhs := range lhs {
			lhs.typ = obj.typ
		}
	}

	check.initVars(lhs, []syntax.Expr{init}, nil)
}

// isImportedConstraint reports whether typ is an imported type constraint.
func (check *Checker) isImportedConstraint(typ Type) bool {
	named := asNamed(typ)
	if named == nil || named.obj.pkg == check.pkg || named.obj.pkg == nil {
		return false
	}
	u, _ := named.under().(*Interface)
	return u != nil && !u.IsMethodSet()
}

func (check *Checker) typeDecl(obj *TypeName, tdecl *syntax.TypeDecl, def *TypeName) {
	assert(obj.typ == nil)

	// Only report a version error if we have not reported one already.
	versionErr := false

	var rhs Type
	check.later(func() {
		if t := asNamed(obj.typ); t != nil { // type may be invalid
			check.validType(t)
		}
		// If typ is local, an error was already reported where typ is specified/defined.
		_ = !versionErr && check.isImportedConstraint(rhs) && check.verifyVersionf(tdecl.Type, go1_18, "using type constraint %s", rhs)
	}).describef(obj, "validType(%s)", obj.Name())

	// First type parameter, or nil.
	var tparam0 *syntax.Field
	if len(tdecl.TParamList) > 0 {
		tparam0 = tdecl.TParamList[0]
	}

	// alias declaration
	if tdecl.Alias {
		// Report highest version requirement first so that fixing a version issue
		// avoids possibly two -lang changes (first to Go 1.9 and then to Go 1.23).
		if !versionErr && tparam0 != nil && !check.verifyVersionf(tparam0, go1_23, "generic type alias") {
			versionErr = true
		}
		if !versionErr && !check.verifyVersionf(tdecl, go1_9, "type alias") {
			versionErr = true
		}

		if check.conf.EnableAlias {
			// TODO(gri) Should be able to use nil instead of Typ[Invalid] to mark
			//           the alias as incomplete. Currently this causes problems
			//           with certain cycles. Investigate.
			//
			// NOTE(adonovan): to avoid the Invalid being prematurely observed
			// by (e.g.) a var whose type is an unfinished cycle,
			// Unalias does not memoize if Invalid. Perhaps we should use a
			// special sentinel distinct from Invalid.
			alias := check.newAlias(obj, Typ[Invalid])
			setDefType(def, alias)

			// handle type parameters even if not allowed (Alias type is supported)
			if tparam0 != nil {
				if !versionErr && !buildcfg.Experiment.AliasTypeParams {
					check.error(tdecl, UnsupportedFeature, "generic type alias requires GOEXPERIMENT=aliastypeparams")
					versionErr = true
				}
				check.openScope(tdecl, "type parameters")
				defer check.closeScope()
				check.collectTypeParams(&alias.tparams, tdecl.TParamList)
			}

			rhs = check.definedType(tdecl.Type, obj)
			assert(rhs != nil)
			alias.fromRHS = rhs
			Unalias(alias) // resolve alias.actual
		} else {
			if !versionErr && tparam0 != nil {
				check.error(tdecl, UnsupportedFeature, "generic type alias requires GODEBUG=gotypesalias=1 or unset")
				versionErr = true
			}

			check.brokenAlias(obj)
			rhs = check.typ(tdecl.Type)
			check.validAlias(obj, rhs)
		}
		return
	}

	// type definition or generic type declaration
	if !versionErr && tparam0 != nil && !check.verifyVersionf(tparam0, go1_18, "type parameter") {
		versionErr = true
	}

	named := check.newNamed(obj, nil, nil)
	setDefType(def, named)

	if tdecl.TParamList != nil {
		check.openScope(tdecl, "type parameters")
		defer check.closeScope()
		check.collectTypeParams(&named.tparams, tdecl.TParamList)
	}

	// determine underlying type of named
	rhs = check.definedType(tdecl.Type, obj)
	assert(rhs != nil)
	named.fromRHS = rhs

	// If the underlying type was not set while type-checking the right-hand
	// side, it is invalid and an error should have been reported elsewhere.
	if named.underlying == nil {
		named.underlying = Typ[Invalid]
	}

	// Disallow a lone type parameter as the RHS of a type declaration (go.dev/issue/45639).
	// We don't need this restriction anymore if we make the underlying type of a type
	// parameter its constraint interface: if the RHS is a lone type parameter, we will
	// use its underlying type (like we do for any RHS in a type declaration), and its
	// underlying type is an interface and the type declaration is well defined.
	if isTypeParam(rhs) {
		check.error(tdecl.Type, MisplacedTypeParam, "cannot use a type parameter as RHS in type declaration")
		named.underlying = Typ[Invalid]
	}
}

func (check *Checker) collectTypeParams(dst **TypeParamList, list []*syntax.Field) {
	tparams := make([]*TypeParam, len(list))

	// Declare type parameters up-front.
	// The scope of type parameters starts at the beginning of the type parameter
	// list (so we can have mutually recursive parameterized type bounds).
	if len(list) > 0 {
		scopePos := list[0].Pos()
		for i, f := range list {
			tparams[i] = check.declareTypeParam(f.Name, scopePos)
		}
	}

	// Set the type parameters before collecting the type constraints because
	// the parameterized type may be used by the constraints (go.dev/issue/47887).
	// Example: type T[P T[P]] interface{}
	*dst = bindTParams(tparams)

	// Signal to cycle detection that we are in a type parameter list.
	// We can only be inside one type parameter list at any given time:
	// function closures may appear inside a type parameter list but they
	// cannot be generic, and their bodies are processed in delayed and
	// sequential fashion. Note that with each new declaration, we save
	// the existing environment and restore it when done; thus inTParamList
	// is true exactly only when we are in a specific type parameter list.
	assert(!check.inTParamList)
	check.inTParamList = true
	defer func() {
		check.inTParamList = false
	}()

	// Keep track of bounds for later validation.
	var bound Type
	for i, f := range list {
		// Optimization: Re-use the previous type bound if it hasn't changed.
		// This also preserves the grouped output of type parameter lists
		// when printing type strings.
		if i == 0 || f.Type != list[i-1].Type {
			bound = check.bound(f.Type)
			if isTypeParam(bound) {
				// We may be able to allow this since it is now well-defined what
				// the underlying type and thus type set of a type parameter is.
				// But we may need some additional form of cycle detection within
				// type parameter lists.
				check.error(f.Type, MisplacedTypeParam, "cannot use a type parameter as constraint")
				bound = Typ[Invalid]
			}
		}
		tparams[i].bound = bound
	}
}

func (check *Checker) bound(x syntax.Expr) Type {
	// A type set literal of the form ~T and A|B may only appear as constraint;
	// embed it in an implicit interface so that only interface type-checking
	// needs to take care of such type expressions.
	if op, _ := x.(*syntax.Operation); op != nil && (op.Op == syntax.Tilde || op.Op == syntax.Or) {
		t := check.typ(&syntax.InterfaceType{MethodList: []*syntax.Field{{Type: x}}})
		// mark t as implicit interface if all went well
		if t, _ := t.(*Interface); t != nil {
			t.implicit = true
		}
		return t
	}
	return check.typ(x)
}

func (check *Checker) declareTypeParam(name *syntax.Name, scopePos syntax.Pos) *TypeParam {
	// Use Typ[Invalid] for the type constraint to ensure that a type
	// is present even if the actual constraint has not been assigned
	// yet.
	// TODO(gri) Need to systematically review all uses of type parameter
	//           constraints to make sure we don't rely on them if they
	//           are not properly set yet.
	tname := NewTypeName(name.Pos(), check.pkg, name.Value, nil)
	tpar := check.newTypeParam(tname, Typ[Invalid]) // assigns type to tname as a side-effect
	check.declare(check.scope, name, tname, scopePos)
	return tpar
}

func (check *Checker) collectMethods(obj *TypeName) {
	// get associated methods
	// (Checker.collectObjects only collects methods with non-blank names;
	// Checker.resolveBaseTypeName ensures that obj is not an alias name
	// if it has attached methods.)
	methods := check.methods[obj]
	if methods == nil {
		return
	}
	delete(check.methods, obj)
	assert(!check.objMap[obj].tdecl.Alias) // don't use TypeName.IsAlias (requires fully set up object)

	// use an objset to check for name conflicts
	var mset objset

	// spec: "If the base type is a struct type, the non-blank method
	// and field names must be distinct."
	base := asNamed(obj.typ) // shouldn't fail but be conservative
	if base != nil {
		assert(base.TypeArgs().Len() == 0) // collectMethods should not be called on an instantiated type

		// See go.dev/issue/52529: we must delay the expansion of underlying here, as
		// base may not be fully set-up.
		check.later(func() {
			check.checkFieldUniqueness(base)
		}).describef(obj, "verifying field uniqueness for %v", base)

		// Checker.Files may be called multiple times; additional package files
		// may add methods to already type-checked types. Add pre-existing methods
		// so that we can detect redeclarations.
		for i := 0; i < base.NumMethods(); i++ {
			m := base.Method(i)
			assert(m.name != "_")
			assert(mset.insert(m) == nil)
		}
	}

	// add valid methods
	for _, m := range methods {
		// spec: "For a base type, the non-blank names of methods bound
		// to it must be unique."
		assert(m.name != "_")
		if alt := mset.insert(m); alt != nil {
			if alt.Pos().IsKnown() {
				check.errorf(m.pos, DuplicateMethod, "method %s.%s already declared at %v", obj.Name(), m.name, alt.Pos())
			} else {
				check.errorf(m.pos, DuplicateMethod, "method %s.%s already declared", obj.Name(), m.name)
			}
			continue
		}

		if base != nil {
			base.AddMethod(m)
		}
	}
}

func (check *Checker) checkFieldUniqueness(base *Named) {
	if t, _ := base.under().(*Struct); t != nil {
		var mset objset
		for i := 0; i < base.NumMethods(); i++ {
			m := base.Method(i)
			assert(m.name != "_")
			assert(mset.insert(m) == nil)
		}

		// Check that any non-blank field names of base are distinct from its
		// method names.
		for _, fld := range t.fields {
			if fld.name != "_" {
				if alt := mset.insert(fld); alt != nil {
					// Struct fields should already be unique, so we should only
					// encounter an alternate via collision with a method name.
					_ = alt.(*Func)

					// For historical consistency, we report the primary error on the
					// method, and the alt decl on the field.
					err := check.newError(DuplicateFieldAndMethod)
					err.addf(alt, "field and method with the same name %s", fld.name)
					err.addAltDecl(fld)
					err.report()
				}
			}
		}
	}
}

func (check *Checker) funcDecl(obj *Func, decl *declInfo) {
	assert(obj.typ == nil)

	// func declarations cannot use iota
	assert(check.iota == nil)

	sig := new(Signature)
	obj.typ = sig // guard against cycles

	// Avoid cycle error when referring to method while type-checking the signature.
	// This avoids a nuisance in the best case (non-parameterized receiver type) and
	// since the method is not a type, we get an error. If we have a parameterized
	// receiver type, instantiating the receiver type leads to the instantiation of
	// its methods, and we don't want a cycle error in that case.
	// TODO(gri) review if this is correct and/or whether we still need this?
	saved := obj.color_
	obj.color_ = black
	fdecl := decl.fdecl
	check.funcType(sig, fdecl.Recv, fdecl.TParamList, fdecl.Type)
	obj.color_ = saved

	// Set the scope's extent to the complete "func (...) { ... }"
	// so that Scope.Innermost works correctly.
	sig.scope.pos = fdecl.Pos()
	sig.scope.end = syntax.EndPos(fdecl)

	if len(fdecl.TParamList) > 0 && fdecl.Body == nil {
		check.softErrorf(fdecl, BadDecl, "generic function is missing function body")
	}

	// function body must be type-checked after global declarations
	// (functions implemented elsewhere have no body)
	if !check.conf.IgnoreFuncBodies && fdecl.Body != nil {
		check.later(func() {
			check.funcBody(decl, obj.name, sig, fdecl.Body, nil)
		}).describef(obj, "func %s", obj.name)
	}
}

func (check *Checker) declStmt(list []syntax.Decl) {
	pkg := check.pkg

	first := -1                // index of first ConstDecl in the current group, or -1
	var last *syntax.ConstDecl // last ConstDecl with init expressions, or nil
	for index, decl := range list {
		if _, ok := decl.(*syntax.ConstDecl); !ok {
			first = -1 // we're not in a constant declaration
		}

		switch s := decl.(type) {
		case *syntax.ConstDecl:
			top := len(check.delayed)

			// iota is the index of the current constDecl within the group
			if first < 0 || s.Group == nil || list[index-1].(*syntax.ConstDecl).Group != s.Group {
				first = index
				last = nil
			}
			iota := constant.MakeInt64(int64(index - first))

			// determine which initialization expressions to use
			inherited := true
			switch {
			case s.Type != nil || s.Values != nil:
				last = s
				inherited = false
			case last == nil:
				last = new(syntax.ConstDecl) // make sure last exists
				inherited = false
			}

			// declare all constants
			lhs := make([]*Const, len(s.NameList))
			values := syntax.UnpackListExpr(last.Values)
			for i, name := range s.NameList {
				obj := NewConst(name.Pos(), pkg, name.Value, nil, iota)
				lhs[i] = obj

				var init syntax.Expr
				if i < len(values) {
					init = values[i]
				}

				check.constDecl(obj, last.Type, init, inherited)
			}

			// Constants must always have init values.
			check.arity(s.Pos(), s.NameList, values, true, inherited)

			// process function literals in init expressions before scope changes
			check.processDelayed(top)

			// spec: "The scope of a constant or variable identifier declared
			// inside a function begins at the end of the ConstSpec or VarSpec
			// (ShortVarDecl for short variable declarations) and ends at the
			// end of the innermost containing block."
			scopePos := syntax.EndPos(s)
			for i, name := range s.NameList {
				check.declare(check.scope, name, lhs[i], scopePos)
			}

		case *syntax.VarDecl:
			top := len(check.delayed)

			lhs0 := make([]*Var, len(s.NameList))
			for i, name := range s.NameList {
				lhs0[i] = NewVar(name.Pos(), pkg, name.Value, nil)
			}

			// initialize all variables
			values := syntax.UnpackListExpr(s.Values)
			for i, obj := range lhs0 {
				var lhs []*Var
				var init syntax.Expr
				switch len(values) {
				case len(s.NameList):
					// lhs and rhs match
					init = values[i]
				case 1:
					// rhs is expected to be a multi-valued expression
					lhs = lhs0
					init = values[0]
				default:
					if i < len(values) {
						init = values[i]
					}
				}
				check.varDecl(obj, lhs, s.Type, init)
				if len(values) == 1 {
					// If we have a single lhs variable we are done either way.
					// If we have a single rhs expression, it must be a multi-
					// valued expression, in which case handling the first lhs
					// variable will cause all lhs variables to have a type
					// assigned, and we are done as well.
					if debug {
						for _, obj := range lhs0 {
							assert(obj.typ != nil)
						}
					}
					break
				}
			}

			// If we have no type, we must have values.
			if s.Type == nil || values != nil {
				check.arity(s.Pos(), s.NameList, values, false, false)
			}

			// process function literals in init expressions before scope changes
			check.processDelayed(top)

			// declare all variables
			// (only at this point are the variable scopes (parents) set)
			scopePos := syntax.EndPos(s) // see constant declarations
			for i, name := range s.NameList {
				// see constant declarations
				check.declare(check.scope, name, lhs0[i], scopePos)
			}

		case *syntax.TypeDecl:
			obj := NewTypeName(s.Name.Pos(), pkg, s.Name.Value, nil)
			// spec: "The scope of a type identifier declared inside a function
			// begins at the identifier in the TypeSpec and ends at the end of
			// the innermost containing block."
			scopePos := s.Name.Pos()
			check.declare(check.scope, s.Name, obj, scopePos)
			// mark and unmark type before calling typeDecl; its type is still nil (see Checker.objDecl)
			obj.setColor(grey + color(check.push(obj)))
			check.typeDecl(obj, s, nil)
			check.pop().setColor(black)

		default:
			check.errorf(s, InvalidSyntaxTree, "unknown syntax.Decl node %T", s)
		}
	}
}

"""



```