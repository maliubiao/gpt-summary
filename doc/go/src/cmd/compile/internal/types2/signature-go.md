Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the `signature.go` file, specifically the `Signature` struct and related functions within the `types2` package. The request also asks for examples, potential errors, and connections to broader Go features.

2. **Identify the Core Data Structure:** The `Signature` struct is the central element. Examine its fields:
    * `rparams`: Receiver type parameters. This immediately suggests generics and methods with type constraints on the receiver.
    * `tparams`: Regular type parameters. This is another indicator of generics, but for the function/method itself.
    * `scope`:  A scope associated with the signature. This is crucial for understanding how names are resolved within the function/method.
    * `recv`: The receiver variable. This distinguishes methods from regular functions.
    * `params`: Input parameters.
    * `results`: Return values.
    * `variadic`:  Indicates a variadic function/method (using `...`).

3. **Analyze Key Functions:** Go through the functions defined within the snippet:
    * `NewSignatureType`:  This is a constructor. Pay close attention to the validation logic (variadic checks, constraints on `recv` and `typeParams`). This reveals rules about how signatures can be constructed.
    * `Recv`, `TypeParams`, `RecvTypeParams`, `Params`, `Results`, `Variadic`, `Underlying`, `String`: These are accessor methods, providing ways to retrieve information about the `Signature`. `Underlying` and `String` are interface implementations, which hints at the role of `Signature` within the broader type system.
    * `funcType`: This function seems like the core logic for *creating* a `Signature` from syntax tree elements (`syntax.FuncType`, `syntax.Field`). The use of `Checker` suggests this is part of the type-checking process. Note the calls to `openScope`, `closeScope`, `collectRecv`, `collectTypeParams`, `collectParams`, and `declareParams`. This gives a high-level view of the signature creation process.
    * `collectRecv`:  Specifically handles the receiver part of a method signature. The unpacking of the receiver type and handling of receiver type parameters is key here. The comments about generics and error conditions are important.
    * `unpointer`: A utility function for removing pointer indirections.
    * `recordParenthesizedRecvTypes`:  Deals with how parenthesized receiver types are recorded. This is a detail but important for accurate type representation.
    * `collectParams`:  Handles parsing and type-checking of function/method parameters, including variadic parameters.
    * `declareParams`: Adds parameters to the current scope.
    * `validRecv`:  Performs validation on the receiver type, ensuring it adheres to Go's rules for method receivers.
    * `isCGoTypeObj`: A helper to identify types originating from CGo.

4. **Infer Overall Functionality:** Based on the structure and functions, it's clear that this code is responsible for representing and constructing the signature (type) of functions and methods in Go. This involves:
    * Handling regular functions and methods.
    * Supporting generics (type parameters for both the function/method and the receiver).
    * Managing parameters (including variadic ones) and return values.
    * Enforcing Go's type system rules for signatures, especially method receivers.
    * Integrating with the type-checking process (`Checker`).

5. **Construct Examples:**  Think about how these features manifest in Go code.
    * **Simple Function:** A basic function with parameters and return values.
    * **Method:** A method associated with a struct.
    * **Generic Function:** A function with type parameters.
    * **Generic Method:** A method with receiver type parameters.
    * **Variadic Function:** A function accepting a variable number of arguments.

6. **Identify Error Points:** Examine the validation logic in `NewSignatureType` and `validRecv`. Consider common mistakes developers might make when defining functions or methods. Focus on:
    * Incorrect use of variadic parameters.
    * Invalid receiver types (pointers, interfaces, non-local types).
    * Trying to define methods on instantiated generic types or aliases.
    * Incorrect number of type parameters in receiver specifications.

7. **Connect to Go Features:**  Explicitly link the code to core Go concepts:
    * Functions and methods.
    * Generics (type parameters).
    * The `...` syntax for variadic functions.
    * Method receivers.
    * The distinction between types and their underlying representations.
    * The role of the compiler and type checker.

8. **Address Specific Questions:** Go back to the original request and ensure all points are covered:
    * Listing functionalities:  Done by summarizing the purpose of the structs and functions.
    * Code examples:  Provided with explanations.
    * Input/Output of code: Described for the examples.
    * Command-line arguments:  Recognize that this specific snippet *doesn't* directly handle command-line arguments, as it's part of the compiler's internal workings. Mention this explicitly.
    * Common mistakes:  Illustrated with examples.

9. **Refine and Organize:** Structure the answer logically, using headings and bullet points for clarity. Ensure the language is precise and easy to understand. For example,  group related functionalities together.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus solely on the `Signature` struct.
* **Correction:** Realize the importance of the related functions like `NewSignatureType` and `funcType` for understanding how `Signature` objects are created and used.
* **Initial thought:** Provide very basic examples.
* **Refinement:** Include examples that showcase the more complex features like generics and variadic functions.
* **Initial thought:** Miss the nuance of when type parameters are declared in `collectRecv`.
* **Correction:** Pay closer attention to the comments and code within `collectRecv` to understand the scoping rules for receiver type parameters.
* **Initial thought:** Assume command-line arguments are relevant.
* **Correction:** Recognize that this is an internal compiler component and doesn't directly process command-line arguments in the same way a standalone program would. Clarify this distinction.

By following this structured approach, combining code analysis with understanding of Go's type system, one can effectively explain the functionality of the given code snippet and address all aspects of the request.
`go/src/cmd/compile/internal/types2/signature.go` 文件是 Go 语言编译器 `cmd/compile` 中 `types2` 包的一部分，它主要负责表示和处理函数以及方法的签名信息。

以下是该文件的主要功能：

**1. 定义 `Signature` 结构体:**

   - `Signature` 结构体是该文件最核心的部分，它用于表示一个函数或方法的类型签名。
   - 包含了接收者（`recv`）、类型参数（`tparams`）、接收者类型参数（`rparams`）、参数（`params`）、返回值（`results`）以及是否是变参函数（`variadic`）等信息。
   - 注意到 `scope` 字段的存在，这允许在 `Signature` 中保存作用域信息，主要用于处理函数字面量的情况。

**2. 提供创建 `Signature` 的方法:**

   - `NewSignatureType` 函数用于创建一个新的 `Signature` 类型实例。
   - 它接收接收者、接收者类型参数、类型参数、参数、返回值以及是否是变参等信息作为输入。
   - 在创建过程中，会进行一些基本的校验，例如变参函数必须至少有一个参数，并且最后一个参数的类型必须是 slice 或 string。
   - 还会检查接收者类型参数和普通类型参数是否冲突。

**3. 提供访问 `Signature` 信息的接口方法:**

   - 提供了 `Recv`、`TypeParams`、`RecvTypeParams`、`Params`、`Results`、`Variadic` 等方法，用于获取 `Signature` 结构体中存储的各种信息。
   - `Underlying` 方法返回 `Signature` 自身，因为它本身就代表了一种类型。
   - `String` 方法返回 `Signature` 的字符串表示形式。

**4. 实现函数和方法类型的类型检查逻辑 (`funcType`):**

   - `funcType` 方法是 `Checker` 结构体的一个方法，用于对函数或方法类型进行类型检查。
   - 它会打开一个新的作用域，用于处理函数或方法内部的声明。
   - 调用 `collectRecv` 处理方法接收者。
   - 调用 `collectTypeParams` 处理类型参数。
   - 调用 `collectParams` 处理普通参数和返回值。
   - 声明接收者、普通参数和返回值到当前作用域。
   - 最终填充 `Signature` 结构体的各个字段。

**5. 处理方法接收者 (`collectRecv`):**

   - `collectRecv` 函数负责从语法树节点中提取方法接收者的信息，包括接收者变量和接收者类型参数。
   - 它会解析接收者类型，并处理接收者类型参数的声明和绑定。
   - 对接收者类型进行一些合法性检查，例如不能是未命名的 slice 或 map 类型，也不能是实例化后的泛型类型。

**6. 处理函数和方法的参数 (`collectParams`):**

   - `collectParams` 函数用于收集函数或方法的参数信息，包括参数名和参数类型。
   - 它会处理变参的情况，并将最后一个参数的类型转换为 slice 类型。
   - 记录匿名参数的信息。

**7. 声明参数到作用域 (`declareParams`):**

   - `declareParams` 函数将具名的参数声明到当前的作用域中，以便在函数或方法体内部可以引用这些参数。

**8. 校验方法接收者 (`validRecv`):**

   - `validRecv` 函数用于验证方法接收者是否满足 Go 语言规范的要求。
   - 接收者类型必须是 `T` 或 `*T` 的形式，其中 `T` 是一个类型名。
   - 接收者基类型不能是指针或接口类型，并且必须与方法声明在同一个包中。

**可以推理出它是什么 Go 语言功能的实现：**

这个文件是 Go 语言中**函数和方法的类型系统**实现的关键部分，特别是涉及到以下功能：

* **定义和表示函数和方法类型:**  `Signature` 结构体是对函数和方法签名的抽象表示。
* **泛型函数和方法:** `tparams` 和 `rparams` 字段以及相关的处理逻辑，使得 Go 语言可以支持泛型函数和方法。
* **方法:**  `recv` 字段以及 `collectRecv` 和 `validRecv` 函数的处理，实现了 Go 语言中方法的定义和类型检查。
* **变参函数:** `variadic` 字段和 `collectParams` 函数对 `...` 语法的处理，支持了变参函数的实现。
* **类型检查:** `funcType` 函数将语法树中的函数和方法声明转换为 `Signature` 类型，并在过程中进行类型检查。

**Go 代码举例说明：**

```go
package main

import "fmt"

// 普通函数
func add(a int, b int) int {
	return a + b
}

// 带有接收者的结构体方法
type MyInt int

func (m MyInt) double() MyInt {
	return m * 2
}

// 泛型函数
func max[T comparable](a T, b T) T {
	if a > b {
		return a
	}
	return b
}

// 带有接收者类型参数的泛型方法
type List[T any] []T

func (l List[T]) Print() {
	for _, v := range l {
		fmt.Println(v)
	}
}

// 变参函数
func sum(nums ...int) int {
	total := 0
	for _, num := range nums {
		total += num
	}
	return total
}

func main() {
	fmt.Println(add(1, 2))
	var myNum MyInt = 5
	fmt.Println(myNum.double())
	fmt.Println(max(10, 5))
	stringList := List[string]{"hello", "world"}
	stringList.Print()
	fmt.Println(sum(1, 2, 3, 4))
}
```

在这个例子中，`go/src/cmd/compile/internal/types2/signature.go` 的代码会参与到 `add`、`double`、`max`、`Print` 和 `sum` 这些函数和方法的类型信息的表示和检查中。例如：

* 对于 `add` 函数，会创建一个 `Signature` 实例，其中 `params` 包含两个 `int` 类型的参数，`results` 包含一个 `int` 类型的返回值，`recv` 为 `nil`，`tparams` 和 `rparams` 也为 `nil`。
* 对于 `MyInt.double` 方法，会创建一个 `Signature` 实例，其中 `recv` 指向 `MyInt` 类型的接收者，`params` 和 `results` 分别包含 `MyInt` 类型。
* 对于 `max` 泛型函数，`tparams` 会包含一个类型参数 `T`，其约束是 `comparable`。
* 对于 `List[T].Print` 泛型方法，`rparams` 会包含类型参数 `T`。
* 对于 `sum` 变参函数，`variadic` 字段会为 `true`，并且 `params` 中最后一个参数的类型会是 `[]int`。

**代码推理（假设的输入与输出）：**

假设我们正在编译以下代码片段：

```go
package main

type MyStruct struct {}

func (ms *MyStruct) myMethod(a int) string {
	return fmt.Sprintf("value: %d", a)
}
```

当编译器处理 `myMethod` 的定义时，`funcType` 函数会被调用，并传入与 `myMethod` 相关的语法树节点。

**假设输入:**

* `sig`: 一个空的 `Signature` 结构体实例。
* `recvPar`:  指向 `(ms *MyStruct)` 的语法树节点。
* `tparams`: `nil` (因为 `myMethod` 没有类型参数)。
* `ftyp`: 指向 `func (ms *MyStruct) myMethod(a int) string` 的函数类型语法树节点。

**代码推理过程:**

1. `funcType` 函数会被调用。
2. `check.openScope` 会创建一个新的作用域。
3. `collectRecv` 会被调用，解析 `recvPar`，得到接收者变量 `ms`（类型为 `*MyStruct`）。
4. `collectTypeParams` 不会被调用，因为 `tparams` 为 `nil`。
5. `collectParams` 会被调用两次：
   - 第一次处理参数列表 `(a int)`，得到参数变量 `a`（类型为 `int`）。
   - 第二次处理返回值列表 `string`，得到返回值类型 `string`。
6. `declare` 会将接收者 `ms` 和参数 `a` 声明到当前作用域。
7. `sig.recv` 会被设置为接收者变量 `ms`。
8. `sig.params` 会被设置为包含参数变量 `a` 的 `Tuple`。
9. `sig.results` 会被设置为包含返回值类型 `string` 的 `Tuple`。
10. `sig.variadic` 会被设置为 `false`。

**假设输出 (最终 `sig` 的状态):**

```
&types2.Signature{
    rparams:  nil,
    tparams:  nil,
    scope:    &types2.Scope{...}, // 指向为 myMethod 创建的作用域
    recv:     &types2.Var{Name: "ms", Type: &types2.Pointer{Base: &types2.Named{Obj: &types2.TypeName{Name: "MyStruct", ...}}}, ...},
    params:   &types2.Tuple{Vars: []*types2.Var{&types2.Var{Name: "a", Type: &types2.Basic{Kind: 6, Name: "int"}, ...}}},
    results:  &types2.Tuple{Vars: []*types2.Var{&types2.Var{Name: "", Type: &types2.Basic{Kind: 10, Name: "string"}, ...}}},
    variadic: false,
}
```

**命令行参数的具体处理:**

这个文件本身并不直接处理命令行参数。命令行参数的处理发生在更上层的 `cmd/compile` 包中。当执行 `go build` 或 `go run` 等命令时，命令行参数会被解析，并传递给编译器。编译器会根据参数配置进行不同的编译流程和优化。

`go/src/cmd/compile/internal/types2/signature.go` 只是在类型检查阶段，根据语法树中解析出的函数和方法定义来创建和处理 `Signature` 对象，并不涉及命令行参数的解析。

**使用者易犯错的点:**

虽然这个文件是编译器内部实现，普通 Go 开发者不会直接操作它，但是了解其背后的逻辑可以帮助理解 Go 语言的类型系统，避免一些常见的错误。以下是一些与 `Signature` 相关的常见错误，虽然不是直接由这个文件报错，但其逻辑会参与到这些错误的检测中：

1. **方法接收者类型不符合规范:**
   ```go
   type MyInt int
   // 错误：接收者不能是指针的指针
   func (m **MyInt) invalidMethod() {}

   type MyInterface interface{}
   // 错误：接收者不能是接口类型
   func (i MyInterface) invalidMethod2() {}
   ```
   `validRecv` 函数会检查这些情况并报错。

2. **在非本地类型上定义新方法:**
   ```go
   package main

   import "fmt"

   // 假设 fmt 包中定义了一些类型

   // 错误：不能在非本地类型上定义新方法
   func (s fmt.Stringer) myMethod() {}
   ```
   `validRecv` 函数会检查接收者类型是否是本地类型。

3. **变参函数 `...` 的使用错误:**
   ```go
   package main

   // 错误：... 只能用于最后一个参数
   func invalidVariadic(a ...int, b string) {}

   // 错误：... 前的类型不能是预声明的别名
   type MySlice []int
   func invalidVariadic2(a ...MySlice) {}
   ```
   `collectParams` 函数会检查变参的使用是否正确。

4. **泛型类型和方法定义不匹配:**
   ```go
   package main

   type MyGeneric[T any] struct {}

   // 错误：方法定义中的类型参数数量与接收者类型不匹配
   func (g MyGeneric[int, string]) myMethod() {}
   ```
   虽然这个文件本身不直接报错，但在泛型实例化的过程中，`Signature` 的信息会被用来进行类型匹配和检查。

了解 `go/src/cmd/compile/internal/types2/signature.go` 的功能，可以帮助开发者更深入地理解 Go 语言中函数和方法的类型机制，以及编译器是如何进行类型检查的。这对于编写更健壮和正确的 Go 代码非常有帮助。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/signature.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types2

import (
	"cmd/compile/internal/syntax"
	"fmt"
	. "internal/types/errors"
	"path/filepath"
	"strings"
)

// ----------------------------------------------------------------------------
// API

// A Signature represents a (non-builtin) function or method type.
// The receiver is ignored when comparing signatures for identity.
type Signature struct {
	// We need to keep the scope in Signature (rather than passing it around
	// and store it in the Func Object) because when type-checking a function
	// literal we call the general type checker which returns a general Type.
	// We then unpack the *Signature and use the scope for the literal body.
	rparams  *TypeParamList // receiver type parameters from left to right, or nil
	tparams  *TypeParamList // type parameters from left to right, or nil
	scope    *Scope         // function scope for package-local and non-instantiated signatures; nil otherwise
	recv     *Var           // nil if not a method
	params   *Tuple         // (incoming) parameters from left to right; or nil
	results  *Tuple         // (outgoing) results from left to right; or nil
	variadic bool           // true if the last parameter's type is of the form ...T (or string, for append built-in only)
}

// NewSignatureType creates a new function type for the given receiver,
// receiver type parameters, type parameters, parameters, and results. If
// variadic is set, params must hold at least one parameter and the last
// parameter's core type must be of unnamed slice or bytestring type.
// If recv is non-nil, typeParams must be empty. If recvTypeParams is
// non-empty, recv must be non-nil.
func NewSignatureType(recv *Var, recvTypeParams, typeParams []*TypeParam, params, results *Tuple, variadic bool) *Signature {
	if variadic {
		n := params.Len()
		if n == 0 {
			panic("variadic function must have at least one parameter")
		}
		core := coreString(params.At(n - 1).typ)
		if _, ok := core.(*Slice); !ok && !isString(core) {
			panic(fmt.Sprintf("got %s, want variadic parameter with unnamed slice type or string as core type", core.String()))
		}
	}
	sig := &Signature{recv: recv, params: params, results: results, variadic: variadic}
	if len(recvTypeParams) != 0 {
		if recv == nil {
			panic("function with receiver type parameters must have a receiver")
		}
		sig.rparams = bindTParams(recvTypeParams)
	}
	if len(typeParams) != 0 {
		if recv != nil {
			panic("function with type parameters cannot have a receiver")
		}
		sig.tparams = bindTParams(typeParams)
	}
	return sig
}

// Recv returns the receiver of signature s (if a method), or nil if a
// function. It is ignored when comparing signatures for identity.
//
// For an abstract method, Recv returns the enclosing interface either
// as a *[Named] or an *[Interface]. Due to embedding, an interface may
// contain methods whose receiver type is a different interface.
func (s *Signature) Recv() *Var { return s.recv }

// TypeParams returns the type parameters of signature s, or nil.
func (s *Signature) TypeParams() *TypeParamList { return s.tparams }

// RecvTypeParams returns the receiver type parameters of signature s, or nil.
func (s *Signature) RecvTypeParams() *TypeParamList { return s.rparams }

// Params returns the parameters of signature s, or nil.
func (s *Signature) Params() *Tuple { return s.params }

// Results returns the results of signature s, or nil.
func (s *Signature) Results() *Tuple { return s.results }

// Variadic reports whether the signature s is variadic.
func (s *Signature) Variadic() bool { return s.variadic }

func (s *Signature) Underlying() Type { return s }
func (s *Signature) String() string   { return TypeString(s, nil) }

// ----------------------------------------------------------------------------
// Implementation

// funcType type-checks a function or method type.
func (check *Checker) funcType(sig *Signature, recvPar *syntax.Field, tparams []*syntax.Field, ftyp *syntax.FuncType) {
	check.openScope(ftyp, "function")
	check.scope.isFunc = true
	check.recordScope(ftyp, check.scope)
	sig.scope = check.scope
	defer check.closeScope()

	// collect method receiver, if any
	var recv *Var
	var rparams *TypeParamList
	if recvPar != nil {
		// all type parameters' scopes start after the method name
		scopePos := ftyp.Pos()
		recv, rparams = check.collectRecv(recvPar, scopePos)
	}

	// collect and declare function type parameters
	if tparams != nil {
		// The parser will complain about invalid type parameters for methods.
		check.collectTypeParams(&sig.tparams, tparams)
	}

	// collect ordinary and result parameters
	pnames, params, variadic := check.collectParams(ftyp.ParamList, true)
	rnames, results, _ := check.collectParams(ftyp.ResultList, false)

	// declare named receiver, ordinary, and result parameters
	scopePos := syntax.EndPos(ftyp) // all parameter's scopes start after the signature
	if recv != nil && recv.name != "" {
		check.declare(check.scope, recvPar.Name, recv, scopePos)
	}
	check.declareParams(pnames, params, scopePos)
	check.declareParams(rnames, results, scopePos)

	sig.recv = recv
	sig.rparams = rparams
	sig.params = NewTuple(params...)
	sig.results = NewTuple(results...)
	sig.variadic = variadic
}

// collectRecv extracts the method receiver and its type parameters (if any) from rparam.
// It declares the type parameters (but not the receiver) in the current scope, and
// returns the receiver variable and its type parameter list (if any).
func (check *Checker) collectRecv(rparam *syntax.Field, scopePos syntax.Pos) (*Var, *TypeParamList) {
	// Unpack the receiver parameter which is of the form
	//
	//	"(" [rname] ["*"] rbase ["[" rtparams "]"] ")"
	//
	// The receiver name rname, the pointer indirection, and the
	// receiver type parameters rtparams may not be present.
	rptr, rbase, rtparams := check.unpackRecv(rparam.Type, true)

	// Determine the receiver base type.
	var recvType Type = Typ[Invalid]
	var recvTParamsList *TypeParamList
	if rtparams == nil {
		// If there are no type parameters, we can simply typecheck rparam.Type.
		// If that is a generic type, varType will complain.
		// Further receiver constraints will be checked later, with validRecv.
		// We use rparam.Type (rather than base) to correctly record pointer
		// and parentheses in types2.Info (was bug, see go.dev/issue/68639).
		recvType = check.varType(rparam.Type)
		// Defining new methods on instantiated (alias or defined) types is not permitted.
		// Follow literal pointer/alias type chain and check.
		// (Correct code permits at most one pointer indirection, but for this check it
		// doesn't matter if we have multiple pointers.)
		a, _ := unpointer(recvType).(*Alias) // recvType is not generic per above
		for a != nil {
			baseType := unpointer(a.fromRHS)
			if g, _ := baseType.(genericType); g != nil && g.TypeParams() != nil {
				check.errorf(rbase, InvalidRecv, "cannot define new methods on instantiated type %s", g)
				recvType = Typ[Invalid] // avoid follow-on errors by Checker.validRecv
				break
			}
			a, _ = baseType.(*Alias)
		}
	} else {
		// If there are type parameters, rbase must denote a generic base type.
		// Important: rbase must be resolved before declaring any receiver type
		// parameters (which may have the same name, see below).
		var baseType *Named // nil if not valid
		var cause string
		if t := check.genericType(rbase, &cause); isValid(t) {
			switch t := t.(type) {
			case *Named:
				baseType = t
			case *Alias:
				// Methods on generic aliases are not permitted.
				// Only report an error if the alias type is valid.
				if isValid(unalias(t)) {
					check.errorf(rbase, InvalidRecv, "cannot define new methods on generic alias type %s", t)
				}
				// Ok to continue but do not set basetype in this case so that
				// recvType remains invalid (was bug, see go.dev/issue/70417).
			default:
				panic("unreachable")
			}
		} else {
			if cause != "" {
				check.errorf(rbase, InvalidRecv, "%s", cause)
			}
			// Ok to continue but do not set baseType (see comment above).
		}

		// Collect the type parameters declared by the receiver (see also
		// Checker.collectTypeParams). The scope of the type parameter T in
		// "func (r T[T]) f() {}" starts after f, not at r, so we declare it
		// after typechecking rbase (see go.dev/issue/52038).
		recvTParams := make([]*TypeParam, len(rtparams))
		for i, rparam := range rtparams {
			tpar := check.declareTypeParam(rparam, scopePos)
			recvTParams[i] = tpar
			// For historic reasons, type parameters in receiver type expressions
			// are considered both definitions and uses and thus must be recorded
			// in the Info.Uses and Info.Types maps (see go.dev/issue/68670).
			check.recordUse(rparam, tpar.obj)
			check.recordTypeAndValue(rparam, typexpr, tpar, nil)
		}
		recvTParamsList = bindTParams(recvTParams)

		// Get the type parameter bounds from the receiver base type
		// and set them for the respective (local) receiver type parameters.
		if baseType != nil {
			baseTParams := baseType.TypeParams().list()
			if len(recvTParams) == len(baseTParams) {
				smap := makeRenameMap(baseTParams, recvTParams)
				for i, recvTPar := range recvTParams {
					baseTPar := baseTParams[i]
					check.mono.recordCanon(recvTPar, baseTPar)
					// baseTPar.bound is possibly parameterized by other type parameters
					// defined by the generic base type. Substitute those parameters with
					// the receiver type parameters declared by the current method.
					recvTPar.bound = check.subst(recvTPar.obj.pos, baseTPar.bound, smap, nil, check.context())
				}
			} else {
				got := measure(len(recvTParams), "type parameter")
				check.errorf(rbase, BadRecv, "receiver declares %s, but receiver base type declares %d", got, len(baseTParams))
			}

			// The type parameters declared by the receiver also serve as
			// type arguments for the receiver type. Instantiate the receiver.
			check.verifyVersionf(rbase, go1_18, "type instantiation")
			targs := make([]Type, len(recvTParams))
			for i, targ := range recvTParams {
				targs[i] = targ
			}
			recvType = check.instance(rparam.Type.Pos(), baseType, targs, nil, check.context())
			check.recordInstance(rbase, targs, recvType)

			// Reestablish pointerness if needed (but avoid a pointer to an invalid type).
			if rptr && isValid(recvType) {
				recvType = NewPointer(recvType)
			}

			check.recordParenthesizedRecvTypes(rparam.Type, recvType)
		}
	}

	// Create the receiver parameter.
	// recvType is invalid if baseType was never set.
	var recv *Var
	if rname := rparam.Name; rname != nil && rname.Value != "" {
		// named receiver
		recv = NewParam(rname.Pos(), check.pkg, rname.Value, recvType)
		// In this case, the receiver is declared by the caller
		// because it must be declared after any type parameters
		// (otherwise it might shadow one of them).
	} else {
		// anonymous receiver
		recv = NewParam(rparam.Pos(), check.pkg, "", recvType)
		check.recordImplicit(rparam, recv)
	}

	// Delay validation of receiver type as it may cause premature expansion of types
	// the receiver type is dependent on (see go.dev/issue/51232, go.dev/issue/51233).
	check.later(func() {
		check.validRecv(rbase, recv)
	}).describef(recv, "validRecv(%s)", recv)

	return recv, recvTParamsList
}

func unpointer(t Type) Type {
	for {
		p, _ := t.(*Pointer)
		if p == nil {
			return t
		}
		t = p.base
	}
}

// recordParenthesizedRecvTypes records parenthesized intermediate receiver type
// expressions that all map to the same type, by recursively unpacking expr and
// recording the corresponding type for it. Example:
//
//	expression  -->  type
//	----------------------
//	(*(T[P]))        *T[P]
//	 *(T[P])         *T[P]
//	  (T[P])          T[P]
//	   T[P]           T[P]
func (check *Checker) recordParenthesizedRecvTypes(expr syntax.Expr, typ Type) {
	for {
		check.recordTypeAndValue(expr, typexpr, typ, nil)
		switch e := expr.(type) {
		case *syntax.ParenExpr:
			expr = e.X
		case *syntax.Operation:
			if e.Op == syntax.Mul && e.Y == nil {
				expr = e.X
				// In a correct program, typ must be an unnamed
				// pointer type. But be careful and don't panic.
				ptr, _ := typ.(*Pointer)
				if ptr == nil {
					return // something is wrong
				}
				typ = ptr.base
				break
			}
			return // cannot unpack any further
		default:
			return // cannot unpack any further
		}
	}
}

// collectParams collects (but does not declare) all parameters of list and returns
// the list of parameter names, corresponding parameter variables, and whether the
// parameter list is variadic. Anonymous parameters are recorded with nil names.
func (check *Checker) collectParams(list []*syntax.Field, variadicOk bool) (names []*syntax.Name, params []*Var, variadic bool) {
	if list == nil {
		return
	}

	var named, anonymous bool

	var typ Type
	var prev syntax.Expr
	for i, field := range list {
		ftype := field.Type
		// type-check type of grouped fields only once
		if ftype != prev {
			prev = ftype
			if t, _ := ftype.(*syntax.DotsType); t != nil {
				ftype = t.Elem
				if variadicOk && i == len(list)-1 {
					variadic = true
				} else {
					check.softErrorf(t, MisplacedDotDotDot, "can only use ... with final parameter in list")
					// ignore ... and continue
				}
			}
			typ = check.varType(ftype)
		}
		// The parser ensures that f.Tag is nil and we don't
		// care if a constructed AST contains a non-nil tag.
		if field.Name != nil {
			// named parameter
			name := field.Name.Value
			if name == "" {
				check.error(field.Name, InvalidSyntaxTree, "anonymous parameter")
				// ok to continue
			}
			par := NewParam(field.Name.Pos(), check.pkg, name, typ)
			// named parameter is declared by caller
			names = append(names, field.Name)
			params = append(params, par)
			named = true
		} else {
			// anonymous parameter
			par := NewParam(field.Pos(), check.pkg, "", typ)
			check.recordImplicit(field, par)
			names = append(names, nil)
			params = append(params, par)
			anonymous = true
		}
	}

	if named && anonymous {
		check.error(list[0], InvalidSyntaxTree, "list contains both named and anonymous parameters")
		// ok to continue
	}

	// For a variadic function, change the last parameter's type from T to []T.
	// Since we type-checked T rather than ...T, we also need to retro-actively
	// record the type for ...T.
	if variadic {
		last := params[len(params)-1]
		last.typ = &Slice{elem: last.typ}
		check.recordTypeAndValue(list[len(list)-1].Type, typexpr, last.typ, nil)
	}

	return
}

// declareParams declares each named parameter in the current scope.
func (check *Checker) declareParams(names []*syntax.Name, params []*Var, scopePos syntax.Pos) {
	for i, name := range names {
		if name != nil && name.Value != "" {
			check.declare(check.scope, name, params[i], scopePos)
		}
	}
}

// validRecv verifies that the receiver satisfies its respective spec requirements
// and reports an error otherwise.
func (check *Checker) validRecv(pos poser, recv *Var) {
	// spec: "The receiver type must be of the form T or *T where T is a type name."
	rtyp, _ := deref(recv.typ)
	atyp := Unalias(rtyp)
	if !isValid(atyp) {
		return // error was reported before
	}
	// spec: "The type denoted by T is called the receiver base type; it must not
	// be a pointer or interface type and it must be declared in the same package
	// as the method."
	switch T := atyp.(type) {
	case *Named:
		if T.obj.pkg != check.pkg || isCGoTypeObj(T.obj) {
			check.errorf(pos, InvalidRecv, "cannot define new methods on non-local type %s", rtyp)
			break
		}
		var cause string
		switch u := T.under().(type) {
		case *Basic:
			// unsafe.Pointer is treated like a regular pointer
			if u.kind == UnsafePointer {
				cause = "unsafe.Pointer"
			}
		case *Pointer, *Interface:
			cause = "pointer or interface type"
		case *TypeParam:
			// The underlying type of a receiver base type cannot be a
			// type parameter: "type T[P any] P" is not a valid declaration.
			panic("unreachable")
		}
		if cause != "" {
			check.errorf(pos, InvalidRecv, "invalid receiver type %s (%s)", rtyp, cause)
		}
	case *Basic:
		check.errorf(pos, InvalidRecv, "cannot define new methods on non-local type %s", rtyp)
	default:
		check.errorf(pos, InvalidRecv, "invalid receiver type %s", recv.typ)
	}
}

// isCGoTypeObj reports whether the given type name was created by cgo.
func isCGoTypeObj(obj *TypeName) bool {
	return strings.HasPrefix(obj.name, "_Ctype_") ||
		strings.HasPrefix(filepath.Base(obj.pos.FileBase().Filename()), "_cgo_")
}
```