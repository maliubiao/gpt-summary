Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding - The Big Picture:**

The first thing to notice is the package declaration: `package types2`. This immediately suggests we're dealing with the type system within the Go compiler (`cmd/compile`). The filename, `infer.go`, strongly indicates this code is responsible for type inference, a core feature of Go's generics. The copyright notice confirms it's part of the official Go repository.

**2. Key Functions and Their Signatures:**

Next, scan for the primary functions. The most prominent one is `infer`. Its signature is quite informative:

```go
func (check *Checker) infer(pos syntax.Pos, tparams []*TypeParam, targs []Type, params *Tuple, args []*operand, reverse bool, err *error_) (inferred []Type)
```

Let's break down the parameters and return value:

* `check *Checker`:  This implies the function is part of a larger type checking process.
* `pos syntax.Pos`:  Indicates a source code position, likely used for error reporting.
* `tparams []*TypeParam`: A slice of type parameters, the things we're trying to infer.
* `targs []Type`:  A slice of already provided type arguments. The inference process tries to fill in any missing ones.
* `params *Tuple`:  The types of the function's parameters.
* `args []*operand`: The actual arguments passed to the function.
* `reverse bool`: A flag, and the comment suggests it's related to "reverse type inference" and error message formatting. This hints at a more advanced or less common scenario.
* `err *error_`:  A pointer to an error object, used to report any issues during inference.
* `inferred []Type`: The return value, a slice of the fully inferred type arguments.

The function signature strongly suggests the core responsibility: given some type parameters, possibly some explicit type arguments, function parameter types, and argument expressions, try to figure out the missing type arguments.

**3. Delving into `infer`'s Logic (High-Level):**

Read through the `infer` function's code, focusing on the major steps and control flow:

* **Assertions and Tracing:**  The `assert` calls and the `traceInference` blocks are for debugging and internal consistency checks. We can mostly skip these for understanding the core logic.
* **Early Exit Conditions:** The function checks for cases where inference isn't needed (all type arguments provided) or impossible (invalid arguments).
* **Substitution:** The code mentions `check.subst`, suggesting a step where type parameters are replaced with known type arguments.
* **Unification:** The `unifier` and `u.unify` are crucial. This points to the core mechanism of matching types and inferring unknown parts. The comments mention "unifying parameter and argument types."
* **Constraint Handling:** The code iterates through type parameters and their constraints, using `coreTerm`. This indicates that the inference process respects the bounds specified for type parameters.
* **Untyped Arguments:**  A separate section deals with how to handle arguments without explicit types (like untyped constants).
* **Simplification:** The "simplify" section with the `killCycles` function is important. It suggests a post-processing step to resolve remaining type parameters and handle potential circular dependencies.
* **Error Reporting:**  The `err.addf` calls are where the function signals failures during inference.

**4. Connecting to Go Language Features:**

Based on the code's structure and the terminology (type parameters, type arguments, constraints), it becomes clear that this code implements type inference for **Go generics**.

**5. Generating Example Code:**

To illustrate the functionality, construct a simple Go example that uses generics and relies on type inference:

```go
package main

import "fmt"

func Print[T any](s T) {
	fmt.Println(s)
}

func main() {
	Print("hello") // Type inference: T is inferred as string
	Print(123)   // Type inference: T is inferred as int
}
```

This example showcases basic type inference where the compiler deduces the type argument `T` based on the argument passed to the generic function.

**6. Considering More Complex Scenarios and Edge Cases:**

Think about more involved uses of generics:

* **Constraints:**  Examples with interfaces as constraints can illustrate how the `coreTerm` and method checking parts of the code come into play.
* **Partially Specified Type Arguments:** Show how explicit type arguments can guide the inference process.
* **Reverse Type Inference:**  While less common, the comment about `enableReverseTypeInference` hints at scenarios like assigning generic functions to variables with specific function types. Construct an example for this.
* **Scenarios Where Inference Fails:** Create cases where the compiler cannot infer the type arguments, leading to errors.

**7. Command-Line Parameters and Error Handling:**

Since this code is part of the compiler, think about how command-line flags might influence its behavior. The provided snippet doesn't directly handle command-line arguments, but recognizing it's part of a larger compilation process is key. The error handling (`err *error_`) is evident in the code.

**8. Common Mistakes:**

Consider the user's perspective and common errors when using generics:

* **Mismatched Types:** Passing arguments that violate constraints.
* **Ambiguous Cases:** Situations where the compiler cannot uniquely determine the type arguments.

**9. Refining and Structuring the Explanation:**

Organize the findings into logical sections:

* **Functionality:** Briefly describe the main purpose of the code.
* **Go Feature Implementation:** Clearly state that it implements type inference for Go generics.
* **Code Examples:** Provide clear and illustrative Go code samples with inputs and expected outputs (or error messages).
* **Reverse Type Inference:** Explain this more advanced feature with an example.
* **Command-Line Arguments:**  Explain that this code is part of the compiler and doesn't directly handle flags, but the overall compilation process does.
* **Common Mistakes:** List typical errors users might encounter.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Might have focused too much on low-level details initially. Realized it's better to start with the high-level purpose and then drill down.
* **Realization:** The `reverse` flag and related comments are important and indicate a specific, possibly newer, feature. Need to research or make an informed guess about what "reverse type inference" entails. (In this case, the comment is quite helpful.)
* **Constraint handling:** Initially might have overlooked the significance of the constraint checking part. The example with the `Stringer` interface helps illustrate this.
* **Error message wording:** Pay attention to how the code generates error messages (`err.addf`). This helps in constructing realistic error scenarios.

By following these steps, combining code analysis with knowledge of Go's features, and thinking from both the compiler's and the user's perspective, a comprehensive explanation of the provided code snippet can be developed.
这段代码是 Go 语言编译器 `cmd/compile/internal/types2` 包中 `infer.go` 文件的一部分，主要负责 **实现 Go 语言泛型的类型参数推断**（type parameter inference）。

以下是它的功能分解和相关说明：

**1. 主要功能：推断泛型函数或方法调用的类型参数**

当调用一个泛型函数或方法，并且没有显式提供所有的类型参数时，Go 编译器需要根据传入的实际参数的类型来推断缺失的类型参数。`infer` 函数就是执行这个推断过程的核心。

**2. `infer` 函数的功能细节：**

* **输入：**
    * `pos syntax.Pos`:  调用发生的位置，用于错误报告。
    * `tparams []*TypeParam`: 泛型函数或方法声明的类型参数列表。
    * `targs []Type`:  调用时已经提供的类型参数列表 (可能为空或部分提供)。
    * `params *Tuple`: 泛型函数或方法的参数类型列表。
    * `args []*operand`: 调用时传入的实际参数的表达式信息。
    * `reverse bool`:  一个标志，用于改进某些反向类型推断相关的错误消息。
    * `err *error_`: 用于报告推断过程中出现的错误。
* **输出：**
    * `inferred []Type`:  一个完整的类型参数列表，包含了已提供的和推断出的类型参数。如果推断失败，则返回 `nil`。

* **推断步骤 (代码逻辑体现)：**
    1. **基本检查：** 确保至少有一个类型参数，提供的类型参数数量不超过类型参数总数，实际参数和形参数量匹配。
    2. **已提供所有类型参数：** 如果已经提供了所有的类型参数，则直接返回。
    3. **无效参数检查：** 如果存在无效的实际参数，则提前返回，避免产生更多的推断错误。
    4. **补全类型参数列表：** 如果提供的类型参数少于总数，则创建一个新的列表并复制已提供的类型参数，剩余部分为 `nil`。
    5. **替换参数类型中的类型参数：**  使用已知的类型参数替换函数参数类型中对应的类型参数，以便获得更清晰的错误消息。
    6. **统一参数和实际参数的类型：** 创建一个 `unifier` 对象，用于统一（unify）泛型参数的类型和实际参数的类型。
       * 对于有类型的实际参数，尝试将参数类型与实际参数类型统一。
       * 对于无类型的实际参数，记录下其对应的泛型参数索引，以便后续处理。
    7. **利用类型参数约束推断：**  遍历类型参数及其约束（constraints），尝试根据约束进一步推断类型参数。
       * 如果类型参数的约束有核心类型（core type），尝试将类型参数与核心类型统一。
       * 检查已推断出的类型参数是否满足约束中定义的方法。
    8. **处理无类型的常量参数：** 对于那些对应于泛型参数且传入的是无类型常量的参数，尝试根据这些常量的默认类型来推断类型参数。
    9. **简化推断结果：** 使用已推断出的类型参数替换其他推断出的类型中的类型参数，直到没有变化为止。这有助于消除类型参数之间的依赖关系。
    10. **消除循环依赖：**  如果推断出的类型中存在循环依赖（例如，类型参数 A 的推断结果包含对 A 的引用），则将该类型参数的推断结果设置为 `nil`，表示无法推断。
    11. **最终检查：**  检查是否还有未推断出的类型参数。如果存在，则报告错误。

**3. 涉及的 Go 语言功能：泛型 (Generics)**

`infer.go` 文件中的 `infer` 函数直接服务于 Go 语言的泛型功能。泛型允许在定义函数、结构体或接口时使用类型参数，从而提高代码的复用性和类型安全性。类型参数推断是泛型中一个非常重要的特性，它使得在调用泛型代码时，通常可以省略显式指定类型参数，编译器会自动推断。

**4. Go 代码示例：**

```go
package main

import "fmt"

// 一个简单的泛型函数
func Print[T any](s T) {
	fmt.Println(s)
}

func main() {
	Print("hello") // 类型推断：T 被推断为 string
	Print(123)   // 类型推断：T 被推断为 int

	type MyInt int
	var myInt MyInt = 42
	Print(myInt) // 类型推断：T 被推断为 main.MyInt

	// 显式指定类型参数（通常不是必须的，除非推断不出来或有歧义）
	Print[float64](3.14)
}
```

**假设的输入与输出 (针对 `Print("hello")` 的调用)：**

* **输入：**
    * `pos`:  `Print("hello")` 在源代码中的位置信息。
    * `tparams`:  `[]*TypeParam{TypeParam{Obj: &TypeName{Name: "T"}, ...}}` (`Print` 函数的类型参数列表)
    * `targs`:  `[]Type{nil}` (没有显式提供类型参数)
    * `params`: `*Tuple{vars: []*Var{{Name: "s", Type: TypeParam{...}}}}` (`Print` 函数的参数类型列表)
    * `args`:  `[]*operand{{expr: "hello", typ: string, ...}}` (实际参数 "hello" 的信息)
    * `reverse`: `false`
    * `err`: `&error_{}` (初始为空的错误对象)
* **输出：**
    * `inferred`: `[]Type{string}` (推断出类型参数 `T` 为 `string`)

**5. 命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。它位于 `cmd/compile/internal/types2` 包中，是 Go 编译器的内部组成部分。命令行参数的处理发生在编译器的更上层，例如 `cmd/compile/internal/gc` 包。

当使用 `go build` 或 `go run` 等命令编译 Go 代码时，编译器会解析命令行参数，然后进行词法分析、语法分析、类型检查等一系列步骤，其中类型参数推断就是类型检查阶段的一部分，由 `infer` 函数负责。

**6. 使用者易犯错的点：**

虽然类型参数推断通常很智能，但使用者在以下情况下可能会遇到问题：

* **类型信息不足导致推断失败：**

```go
func Max[T interface{ ~int | ~float64 }](a, b T) T {
	if a > b {
		return a
	}
	return b
}

func main() {
	// 错误：无法推断类型参数 T
	// Max(1, 1.0)

	// 正确：显式指定类型参数
	fmt.Println(Max[float64](1, 1.0))
}
```
在上面的例子中，`Max(1, 1.0)` 调用中，第一个参数是 `int`，第二个参数是 `float64`。虽然它们的底层类型都满足约束 `~int | ~float64`，但是编译器无法确定 `T` 应该推断为 `int` 还是 `float64`。

* **推断结果不符合预期：**

```go
type MyString string

func Process[T string | MyString](s T) {
	fmt.Printf("Type of s: %T\n", s)
}

func main() {
	var str string = "abc"
	Process(str) // 类型推断：T 被推断为 string

	var myStr MyString = "def"
	Process(myStr) // 类型推断：T 被推断为 main.MyString
}
```
在这个例子中，虽然 `string` 和 `MyString` 都满足约束，但编译器会根据实际参数的类型进行精确推断。有时使用者可能希望都推断为 `string` 或都推断为 `MyString`，但默认行为是根据实际类型推断。

* **与方法接收者相关的推断：**  当调用泛型类型的方法时，类型参数的推断可能涉及到接收者的类型，如果接收者的类型参数没有足够的信息来推断，则可能导致错误。

总而言之，`infer.go` 中的 `infer` 函数是 Go 语言泛型类型推断的核心实现，它根据函数调用时提供的参数信息和类型参数的约束来自动确定泛型类型参数的具体类型，极大地简化了泛型代码的使用。理解其工作原理有助于更好地理解和使用 Go 语言的泛型特性。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/infer.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements type parameter inference.

package types2

import (
	"cmd/compile/internal/syntax"
	"fmt"
	"slices"
	"strings"
)

// If enableReverseTypeInference is set, uninstantiated and
// partially instantiated generic functions may be assigned
// (incl. returned) to variables of function type and type
// inference will attempt to infer the missing type arguments.
// Available with go1.21.
const enableReverseTypeInference = true // disable for debugging

// infer attempts to infer the complete set of type arguments for generic function instantiation/call
// based on the given type parameters tparams, type arguments targs, function parameters params, and
// function arguments args, if any. There must be at least one type parameter, no more type arguments
// than type parameters, and params and args must match in number (incl. zero).
// If reverse is set, an error message's contents are reversed for a better error message for some
// errors related to reverse type inference (where the function call is synthetic).
// If successful, infer returns the complete list of given and inferred type arguments, one for each
// type parameter. Otherwise the result is nil. Errors are reported through the err parameter.
// Note: infer may fail (return nil) due to invalid args operands without reporting additional errors.
func (check *Checker) infer(pos syntax.Pos, tparams []*TypeParam, targs []Type, params *Tuple, args []*operand, reverse bool, err *error_) (inferred []Type) {
	// Don't verify result conditions if there's no error handler installed:
	// in that case, an error leads to an exit panic and the result value may
	// be incorrect. But in that case it doesn't matter because callers won't
	// be able to use it either.
	if check.conf.Error != nil {
		defer func() {
			assert(inferred == nil || len(inferred) == len(tparams) && !slices.Contains(inferred, nil))
		}()
	}

	if traceInference {
		check.dump("== infer : %s%s ➞ %s", tparams, params, targs) // aligned with rename print below
		defer func() {
			check.dump("=> %s ➞ %s\n", tparams, inferred)
		}()
	}

	// There must be at least one type parameter, and no more type arguments than type parameters.
	n := len(tparams)
	assert(n > 0 && len(targs) <= n)

	// Parameters and arguments must match in number.
	assert(params.Len() == len(args))

	// If we already have all type arguments, we're done.
	if len(targs) == n && !slices.Contains(targs, nil) {
		return targs
	}

	// If we have invalid (ordinary) arguments, an error was reported before.
	// Avoid additional inference errors and exit early (go.dev/issue/60434).
	for _, arg := range args {
		if arg.mode == invalid {
			return nil
		}
	}

	// Make sure we have a "full" list of type arguments, some of which may
	// be nil (unknown). Make a copy so as to not clobber the incoming slice.
	if len(targs) < n {
		targs2 := make([]Type, n)
		copy(targs2, targs)
		targs = targs2
	}
	// len(targs) == n

	// Continue with the type arguments we have. Avoid matching generic
	// parameters that already have type arguments against function arguments:
	// It may fail because matching uses type identity while parameter passing
	// uses assignment rules. Instantiate the parameter list with the type
	// arguments we have, and continue with that parameter list.

	// Substitute type arguments for their respective type parameters in params,
	// if any. Note that nil targs entries are ignored by check.subst.
	// We do this for better error messages; it's not needed for correctness.
	// For instance, given:
	//
	//   func f[P, Q any](P, Q) {}
	//
	//   func _(s string) {
	//           f[int](s, s) // ERROR
	//   }
	//
	// With substitution, we get the error:
	//   "cannot use s (variable of type string) as int value in argument to f[int]"
	//
	// Without substitution we get the (worse) error:
	//   "type string of s does not match inferred type int for P"
	// even though the type int was provided (not inferred) for P.
	//
	// TODO(gri) We might be able to finesse this in the error message reporting
	//           (which only happens in case of an error) and then avoid doing
	//           the substitution (which always happens).
	if params.Len() > 0 {
		smap := makeSubstMap(tparams, targs)
		params = check.subst(nopos, params, smap, nil, check.context()).(*Tuple)
	}

	// Unify parameter and argument types for generic parameters with typed arguments
	// and collect the indices of generic parameters with untyped arguments.
	// Terminology: generic parameter = function parameter with a type-parameterized type
	u := newUnifier(tparams, targs, check.allowVersion(go1_21))

	errorf := func(tpar, targ Type, arg *operand) {
		// provide a better error message if we can
		targs := u.inferred(tparams)
		if targs[0] == nil {
			// The first type parameter couldn't be inferred.
			// If none of them could be inferred, don't try
			// to provide the inferred type in the error msg.
			allFailed := true
			for _, targ := range targs {
				if targ != nil {
					allFailed = false
					break
				}
			}
			if allFailed {
				err.addf(arg, "type %s of %s does not match %s (cannot infer %s)", targ, arg.expr, tpar, typeParamsString(tparams))
				return
			}
		}
		smap := makeSubstMap(tparams, targs)
		// TODO(gri): pass a poser here, rather than arg.Pos().
		inferred := check.subst(arg.Pos(), tpar, smap, nil, check.context())
		// CannotInferTypeArgs indicates a failure of inference, though the actual
		// error may be better attributed to a user-provided type argument (hence
		// InvalidTypeArg). We can't differentiate these cases, so fall back on
		// the more general CannotInferTypeArgs.
		if inferred != tpar {
			if reverse {
				err.addf(arg, "inferred type %s for %s does not match type %s of %s", inferred, tpar, targ, arg.expr)
			} else {
				err.addf(arg, "type %s of %s does not match inferred type %s for %s", targ, arg.expr, inferred, tpar)
			}
		} else {
			err.addf(arg, "type %s of %s does not match %s", targ, arg.expr, tpar)
		}
	}

	// indices of generic parameters with untyped arguments, for later use
	var untyped []int

	// --- 1 ---
	// use information from function arguments

	if traceInference {
		u.tracef("== function parameters: %s", params)
		u.tracef("-- function arguments : %s", args)
	}

	for i, arg := range args {
		if arg.mode == invalid {
			// An error was reported earlier. Ignore this arg
			// and continue, we may still be able to infer all
			// targs resulting in fewer follow-on errors.
			// TODO(gri) determine if we still need this check
			continue
		}
		par := params.At(i)
		if isParameterized(tparams, par.typ) || isParameterized(tparams, arg.typ) {
			// Function parameters are always typed. Arguments may be untyped.
			// Collect the indices of untyped arguments and handle them later.
			if isTyped(arg.typ) {
				if !u.unify(par.typ, arg.typ, assign) {
					errorf(par.typ, arg.typ, arg)
					return nil
				}
			} else if _, ok := par.typ.(*TypeParam); ok && !arg.isNil() {
				// Since default types are all basic (i.e., non-composite) types, an
				// untyped argument will never match a composite parameter type; the
				// only parameter type it can possibly match against is a *TypeParam.
				// Thus, for untyped arguments we only need to look at parameter types
				// that are single type parameters.
				// Also, untyped nils don't have a default type and can be ignored.
				// Finally, it's not possible to have an alias type denoting a type
				// parameter declared by the current function and use it in the same
				// function signature; hence we don't need to Unalias before the
				// .(*TypeParam) type assertion above.
				untyped = append(untyped, i)
			}
		}
	}

	if traceInference {
		inferred := u.inferred(tparams)
		u.tracef("=> %s ➞ %s\n", tparams, inferred)
	}

	// --- 2 ---
	// use information from type parameter constraints

	if traceInference {
		u.tracef("== type parameters: %s", tparams)
	}

	// Unify type parameters with their constraints as long
	// as progress is being made.
	//
	// This is an O(n^2) algorithm where n is the number of
	// type parameters: if there is progress, at least one
	// type argument is inferred per iteration, and we have
	// a doubly nested loop.
	//
	// In practice this is not a problem because the number
	// of type parameters tends to be very small (< 5 or so).
	// (It should be possible for unification to efficiently
	// signal newly inferred type arguments; then the loops
	// here could handle the respective type parameters only,
	// but that will come at a cost of extra complexity which
	// may not be worth it.)
	for i := 0; ; i++ {
		nn := u.unknowns()
		if traceInference {
			if i > 0 {
				fmt.Println()
			}
			u.tracef("-- iteration %d", i)
		}

		for _, tpar := range tparams {
			tx := u.at(tpar)
			core, single := coreTerm(tpar)
			if traceInference {
				u.tracef("-- type parameter %s = %s: core(%s) = %s, single = %v", tpar, tx, tpar, core, single)
			}

			// If the type parameter's constraint has a core term (i.e., a core type with tilde information)
			// try to unify the type parameter with that core type.
			if core != nil {
				// A type parameter can be unified with its constraint's core type in two cases.
				switch {
				case tx != nil:
					if traceInference {
						u.tracef("-> unify type parameter %s (type %s) with constraint core type %s", tpar, tx, core.typ)
					}
					// The corresponding type argument tx is known. There are 2 cases:
					// 1) If the core type has a tilde, per spec requirement for tilde
					//    elements, the core type is an underlying (literal) type.
					//    And because of the tilde, the underlying type of tx must match
					//    against the core type.
					//    But because unify automatically matches a defined type against
					//    an underlying literal type, we can simply unify tx with the
					//    core type.
					// 2) If the core type doesn't have a tilde, we also must unify tx
					//    with the core type.
					if !u.unify(tx, core.typ, 0) {
						// TODO(gri) Type parameters that appear in the constraint and
						//           for which we have type arguments inferred should
						//           use those type arguments for a better error message.
						err.addf(pos, "%s (type %s) does not satisfy %s", tpar, tx, tpar.Constraint())
						return nil
					}
				case single && !core.tilde:
					if traceInference {
						u.tracef("-> set type parameter %s to constraint core type %s", tpar, core.typ)
					}
					// The corresponding type argument tx is unknown and the core term
					// describes a single specific type and no tilde.
					// In this case the type argument must be that single type; set it.
					u.set(tpar, core.typ)
				}
			}

			// Independent of whether there is a core term, if the type argument tx is known
			// it must implement the methods of the type constraint, possibly after unification
			// of the relevant method signatures, otherwise tx cannot satisfy the constraint.
			// This unification step may provide additional type arguments.
			//
			// Note: The type argument tx may be known but contain references to other type
			// parameters (i.e., tx may still be parameterized).
			// In this case the methods of tx don't correctly reflect the final method set
			// and we may get a missing method error below. Skip this step in this case.
			//
			// TODO(gri) We should be able continue even with a parameterized tx if we add
			// a simplify step beforehand (see below). This will require factoring out the
			// simplify phase so we can call it from here.
			if tx != nil && !isParameterized(tparams, tx) {
				if traceInference {
					u.tracef("-> unify type parameter %s (type %s) methods with constraint methods", tpar, tx)
				}
				// TODO(gri) Now that unification handles interfaces, this code can
				//           be reduced to calling u.unify(tx, tpar.iface(), assign)
				//           (which will compare signatures exactly as we do below).
				//           We leave it as is for now because missingMethod provides
				//           a failure cause which allows for a better error message.
				//           Eventually, unify should return an error with cause.
				var cause string
				constraint := tpar.iface()
				if !check.hasAllMethods(tx, constraint, true, func(x, y Type) bool { return u.unify(x, y, exact) }, &cause) {
					// TODO(gri) better error message (see TODO above)
					err.addf(pos, "%s (type %s) does not satisfy %s %s", tpar, tx, tpar.Constraint(), cause)
					return nil
				}
			}
		}

		if u.unknowns() == nn {
			break // no progress
		}
	}

	if traceInference {
		inferred := u.inferred(tparams)
		u.tracef("=> %s ➞ %s\n", tparams, inferred)
	}

	// --- 3 ---
	// use information from untyped constants

	if traceInference {
		u.tracef("== untyped arguments: %v", untyped)
	}

	// Some generic parameters with untyped arguments may have been given a type by now.
	// Collect all remaining parameters that don't have a type yet and determine the
	// maximum untyped type for each of those parameters, if possible.
	var maxUntyped map[*TypeParam]Type // lazily allocated (we may not need it)
	for _, index := range untyped {
		tpar := params.At(index).typ.(*TypeParam) // is type parameter (no alias) by construction of untyped
		if u.at(tpar) == nil {
			arg := args[index] // arg corresponding to tpar
			if maxUntyped == nil {
				maxUntyped = make(map[*TypeParam]Type)
			}
			max := maxUntyped[tpar]
			if max == nil {
				max = arg.typ
			} else {
				m := maxType(max, arg.typ)
				if m == nil {
					err.addf(arg, "mismatched types %s and %s (cannot infer %s)", max, arg.typ, tpar)
					return nil
				}
				max = m
			}
			maxUntyped[tpar] = max
		}
	}
	// maxUntyped contains the maximum untyped type for each type parameter
	// which doesn't have a type yet. Set the respective default types.
	for tpar, typ := range maxUntyped {
		d := Default(typ)
		assert(isTyped(d))
		u.set(tpar, d)
	}

	// --- simplify ---

	// u.inferred(tparams) now contains the incoming type arguments plus any additional type
	// arguments which were inferred. The inferred non-nil entries may still contain
	// references to other type parameters found in constraints.
	// For instance, for [A any, B interface{ []C }, C interface{ *A }], if A == int
	// was given, unification produced the type list [int, []C, *A]. We eliminate the
	// remaining type parameters by substituting the type parameters in this type list
	// until nothing changes anymore.
	inferred = u.inferred(tparams)
	if debug {
		for i, targ := range targs {
			assert(targ == nil || inferred[i] == targ)
		}
	}

	// The data structure of each (provided or inferred) type represents a graph, where
	// each node corresponds to a type and each (directed) vertex points to a component
	// type. The substitution process described above repeatedly replaces type parameter
	// nodes in these graphs with the graphs of the types the type parameters stand for,
	// which creates a new (possibly bigger) graph for each type.
	// The substitution process will not stop if the replacement graph for a type parameter
	// also contains that type parameter.
	// For instance, for [A interface{ *A }], without any type argument provided for A,
	// unification produces the type list [*A]. Substituting A in *A with the value for
	// A will lead to infinite expansion by producing [**A], [****A], [********A], etc.,
	// because the graph A -> *A has a cycle through A.
	// Generally, cycles may occur across multiple type parameters and inferred types
	// (for instance, consider [P interface{ *Q }, Q interface{ func(P) }]).
	// We eliminate cycles by walking the graphs for all type parameters. If a cycle
	// through a type parameter is detected, killCycles nils out the respective type
	// (in the inferred list) which kills the cycle, and marks the corresponding type
	// parameter as not inferred.
	//
	// TODO(gri) If useful, we could report the respective cycle as an error. We don't
	//           do this now because type inference will fail anyway, and furthermore,
	//           constraints with cycles of this kind cannot currently be satisfied by
	//           any user-supplied type. But should that change, reporting an error
	//           would be wrong.
	killCycles(tparams, inferred)

	// dirty tracks the indices of all types that may still contain type parameters.
	// We know that nil type entries and entries corresponding to provided (non-nil)
	// type arguments are clean, so exclude them from the start.
	var dirty []int
	for i, typ := range inferred {
		if typ != nil && (i >= len(targs) || targs[i] == nil) {
			dirty = append(dirty, i)
		}
	}

	for len(dirty) > 0 {
		if traceInference {
			u.tracef("-- simplify %s ➞ %s", tparams, inferred)
		}
		// TODO(gri) Instead of creating a new substMap for each iteration,
		// provide an update operation for substMaps and only change when
		// needed. Optimization.
		smap := makeSubstMap(tparams, inferred)
		n := 0
		for _, index := range dirty {
			t0 := inferred[index]
			if t1 := check.subst(nopos, t0, smap, nil, check.context()); t1 != t0 {
				// t0 was simplified to t1.
				// If t0 was a generic function, but the simplified signature t1 does
				// not contain any type parameters anymore, the function is not generic
				// anymore. Remove its type parameters. (go.dev/issue/59953)
				// Note that if t0 was a signature, t1 must be a signature, and t1
				// can only be a generic signature if it originated from a generic
				// function argument. Those signatures are never defined types and
				// thus there is no need to call under below.
				// TODO(gri) Consider doing this in Checker.subst.
				//           Then this would fall out automatically here and also
				//           in instantiation (where we also explicitly nil out
				//           type parameters). See the *Signature TODO in subst.
				if sig, _ := t1.(*Signature); sig != nil && sig.TypeParams().Len() > 0 && !isParameterized(tparams, sig) {
					sig.tparams = nil
				}
				inferred[index] = t1
				dirty[n] = index
				n++
			}
		}
		dirty = dirty[:n]
	}

	// Once nothing changes anymore, we may still have type parameters left;
	// e.g., a constraint with core type *P may match a type parameter Q but
	// we don't have any type arguments to fill in for *P or Q (go.dev/issue/45548).
	// Don't let such inferences escape; instead treat them as unresolved.
	for i, typ := range inferred {
		if typ == nil || isParameterized(tparams, typ) {
			obj := tparams[i].obj
			err.addf(pos, "cannot infer %s (declared at %v)", obj.name, obj.pos)
			return nil
		}
	}

	return
}

// renameTParams renames the type parameters in the given type such that each type
// parameter is given a new identity. renameTParams returns the new type parameters
// and updated type. If the result type is unchanged from the argument type, none
// of the type parameters in tparams occurred in the type.
// If typ is a generic function, type parameters held with typ are not changed and
// must be updated separately if desired.
// The positions is only used for debug traces.
func (check *Checker) renameTParams(pos syntax.Pos, tparams []*TypeParam, typ Type) ([]*TypeParam, Type) {
	// For the purpose of type inference we must differentiate type parameters
	// occurring in explicit type or value function arguments from the type
	// parameters we are solving for via unification because they may be the
	// same in self-recursive calls:
	//
	//   func f[P constraint](x P) {
	//           f(x)
	//   }
	//
	// In this example, without type parameter renaming, the P used in the
	// instantiation f[P] has the same pointer identity as the P we are trying
	// to solve for through type inference. This causes problems for type
	// unification. Because any such self-recursive call is equivalent to
	// a mutually recursive call, type parameter renaming can be used to
	// create separate, disentangled type parameters. The above example
	// can be rewritten into the following equivalent code:
	//
	//   func f[P constraint](x P) {
	//           f2(x)
	//   }
	//
	//   func f2[P2 constraint](x P2) {
	//           f(x)
	//   }
	//
	// Type parameter renaming turns the first example into the second
	// example by renaming the type parameter P into P2.
	if len(tparams) == 0 {
		return nil, typ // nothing to do
	}

	tparams2 := make([]*TypeParam, len(tparams))
	for i, tparam := range tparams {
		tname := NewTypeName(tparam.Obj().Pos(), tparam.Obj().Pkg(), tparam.Obj().Name(), nil)
		tparams2[i] = NewTypeParam(tname, nil)
		tparams2[i].index = tparam.index // == i
	}

	renameMap := makeRenameMap(tparams, tparams2)
	for i, tparam := range tparams {
		tparams2[i].bound = check.subst(pos, tparam.bound, renameMap, nil, check.context())
	}

	return tparams2, check.subst(pos, typ, renameMap, nil, check.context())
}

// typeParamsString produces a string containing all the type parameter names
// in list suitable for human consumption.
func typeParamsString(list []*TypeParam) string {
	// common cases
	n := len(list)
	switch n {
	case 0:
		return ""
	case 1:
		return list[0].obj.name
	case 2:
		return list[0].obj.name + " and " + list[1].obj.name
	}

	// general case (n > 2)
	var buf strings.Builder
	for i, tname := range list[:n-1] {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(tname.obj.name)
	}
	buf.WriteString(", and ")
	buf.WriteString(list[n-1].obj.name)
	return buf.String()
}

// isParameterized reports whether typ contains any of the type parameters of tparams.
// If typ is a generic function, isParameterized ignores the type parameter declarations;
// it only considers the signature proper (incoming and result parameters).
func isParameterized(tparams []*TypeParam, typ Type) bool {
	w := tpWalker{
		tparams: tparams,
		seen:    make(map[Type]bool),
	}
	return w.isParameterized(typ)
}

type tpWalker struct {
	tparams []*TypeParam
	seen    map[Type]bool
}

func (w *tpWalker) isParameterized(typ Type) (res bool) {
	// detect cycles
	if x, ok := w.seen[typ]; ok {
		return x
	}
	w.seen[typ] = false
	defer func() {
		w.seen[typ] = res
	}()

	switch t := typ.(type) {
	case *Basic:
		// nothing to do

	case *Alias:
		return w.isParameterized(Unalias(t))

	case *Array:
		return w.isParameterized(t.elem)

	case *Slice:
		return w.isParameterized(t.elem)

	case *Struct:
		return w.varList(t.fields)

	case *Pointer:
		return w.isParameterized(t.base)

	case *Tuple:
		// This case does not occur from within isParameterized
		// because tuples only appear in signatures where they
		// are handled explicitly. But isParameterized is also
		// called by Checker.callExpr with a function result tuple
		// if instantiation failed (go.dev/issue/59890).
		return t != nil && w.varList(t.vars)

	case *Signature:
		// t.tparams may not be nil if we are looking at a signature
		// of a generic function type (or an interface method) that is
		// part of the type we're testing. We don't care about these type
		// parameters.
		// Similarly, the receiver of a method may declare (rather than
		// use) type parameters, we don't care about those either.
		// Thus, we only need to look at the input and result parameters.
		return t.params != nil && w.varList(t.params.vars) || t.results != nil && w.varList(t.results.vars)

	case *Interface:
		tset := t.typeSet()
		for _, m := range tset.methods {
			if w.isParameterized(m.typ) {
				return true
			}
		}
		return tset.is(func(t *term) bool {
			return t != nil && w.isParameterized(t.typ)
		})

	case *Map:
		return w.isParameterized(t.key) || w.isParameterized(t.elem)

	case *Chan:
		return w.isParameterized(t.elem)

	case *Named:
		for _, t := range t.TypeArgs().list() {
			if w.isParameterized(t) {
				return true
			}
		}

	case *TypeParam:
		return slices.Index(w.tparams, t) >= 0

	default:
		panic(fmt.Sprintf("unexpected %T", typ))
	}

	return false
}

func (w *tpWalker) varList(list []*Var) bool {
	for _, v := range list {
		if w.isParameterized(v.typ) {
			return true
		}
	}
	return false
}

// If the type parameter has a single specific type S, coreTerm returns (S, true).
// Otherwise, if tpar has a core type T, it returns a term corresponding to that
// core type and false. In that case, if any term of tpar has a tilde, the core
// term has a tilde. In all other cases coreTerm returns (nil, false).
func coreTerm(tpar *TypeParam) (*term, bool) {
	n := 0
	var single *term // valid if n == 1
	var tilde bool
	tpar.is(func(t *term) bool {
		if t == nil {
			assert(n == 0)
			return false // no terms
		}
		n++
		single = t
		if t.tilde {
			tilde = true
		}
		return true
	})
	if n == 1 {
		if debug {
			assert(debug && under(single.typ) == coreType(tpar))
		}
		return single, true
	}
	if typ := coreType(tpar); typ != nil {
		// A core type is always an underlying type.
		// If any term of tpar has a tilde, we don't
		// have a precise core type and we must return
		// a tilde as well.
		return &term{tilde, typ}, false
	}
	return nil, false
}

// killCycles walks through the given type parameters and looks for cycles
// created by type parameters whose inferred types refer back to that type
// parameter, either directly or indirectly. If such a cycle is detected,
// it is killed by setting the corresponding inferred type to nil.
//
// TODO(gri) Determine if we can simply abort inference as soon as we have
// found a single cycle.
func killCycles(tparams []*TypeParam, inferred []Type) {
	w := cycleFinder{tparams, inferred, make(map[Type]bool)}
	for _, t := range tparams {
		w.typ(t) // t != nil
	}
}

type cycleFinder struct {
	tparams  []*TypeParam
	inferred []Type
	seen     map[Type]bool
}

func (w *cycleFinder) typ(typ Type) {
	typ = Unalias(typ)
	if w.seen[typ] {
		// We have seen typ before. If it is one of the type parameters
		// in w.tparams, iterative substitution will lead to infinite expansion.
		// Nil out the corresponding type which effectively kills the cycle.
		if tpar, _ := typ.(*TypeParam); tpar != nil {
			if i := slices.Index(w.tparams, tpar); i >= 0 {
				// cycle through tpar
				w.inferred[i] = nil
			}
		}
		// If we don't have one of our type parameters, the cycle is due
		// to an ordinary recursive type and we can just stop walking it.
		return
	}
	w.seen[typ] = true
	defer delete(w.seen, typ)

	switch t := typ.(type) {
	case *Basic:
		// nothing to do

	// *Alias:
	//      This case should not occur because of Unalias(typ) at the top.

	case *Array:
		w.typ(t.elem)

	case *Slice:
		w.typ(t.elem)

	case *Struct:
		w.varList(t.fields)

	case *Pointer:
		w.typ(t.base)

	// case *Tuple:
	//      This case should not occur because tuples only appear
	//      in signatures where they are handled explicitly.

	case *Signature:
		if t.params != nil {
			w.varList(t.params.vars)
		}
		if t.results != nil {
			w.varList(t.results.vars)
		}

	case *Union:
		for _, t := range t.terms {
			w.typ(t.typ)
		}

	case *Interface:
		for _, m := range t.methods {
			w.typ(m.typ)
		}
		for _, t := range t.embeddeds {
			w.typ(t)
		}

	case *Map:
		w.typ(t.key)
		w.typ(t.elem)

	case *Chan:
		w.typ(t.elem)

	case *Named:
		for _, tpar := range t.TypeArgs().list() {
			w.typ(tpar)
		}

	case *TypeParam:
		if i := slices.Index(w.tparams, t); i >= 0 && w.inferred[i] != nil {
			w.typ(w.inferred[i])
		}

	default:
		panic(fmt.Sprintf("unexpected %T", typ))
	}
}

func (w *cycleFinder) varList(list []*Var) {
	for _, v := range list {
		w.typ(v.typ)
	}
}
```