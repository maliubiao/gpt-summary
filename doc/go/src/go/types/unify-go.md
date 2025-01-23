Response:
The user wants to understand the functionality of the provided Go code snippet, which is located in `go/src/go/types/unify.go`. I need to explain what the code does, potentially infer the larger Go feature it contributes to, provide code examples demonstrating its use, explain relevant command-line arguments (if any), and point out common pitfalls for users.

**Plan:**

1. **High-level function:** Identify the primary purpose of the `unify.go` file and the `unifier` struct. It's about type unification, so explain that process.
2. **Key components:** Describe the main parts of the code, such as the `unifier` struct, its fields (especially `handles`), and the `unify` and `nify` methods.
3. **Inferred Go feature:**  Based on the code, infer which broader Go functionality this code supports. Type unification is crucial for generics (type parameters).
4. **Code examples:** Create Go code snippets demonstrating how type unification might be used in the context of generics. This will likely involve defining generic functions or types and showing how the unifier helps determine type arguments. I'll need to create plausible input types and show the expected outcome (success or failure of unification).
5. **Command-line arguments:** Examine the code for any handling of command-line flags. The code contains `traceInference`, which seems like a debug flag, but it's a constant, not a command-line parameter. Therefore, I'll state that no direct command-line arguments are handled within this specific snippet, but acknowledge its role in a larger compilation process that might use such arguments.
6. **Common pitfalls:** Think about potential errors users might encounter when working with generics and type unification. This could relate to incorrect type constraints, type mismatches, or misunderstandings about how the unification process works. However, the code is internal to the `go/types` package, so direct end-user errors related *specifically* to this code are less likely. The pitfalls will be more about understanding generics in general.
7. **Language:**  Answer in Chinese.
这段代码是 Go 语言 `types` 包中 `unify.go` 文件的一部分，它实现了**类型统一化 (Type Unification)** 的功能。

**功能列表:**

1. **维护类型参数和推断类型之间的映射:**  `unifier` 结构体中的 `handles` 字段用于存储类型参数 (`*TypeParam`) 到其推断出的类型 (`Type`) 的映射。
2. **尝试使两个类型结构上等价:** `unify` 和 `nify` 方法尝试通过为给定的类型参数列表确定类型，使得两个类型 `x` 和 `y` 在结构上等价。
3. **记录类型参数的推断结果:**  如果统一化成功，作为副作用，会记录或更新绑定类型参数的类型。
4. **处理不同模式的统一化:**  `unifyMode` 类型定义了不同的统一化模式，例如 `exact` 模式要求类型完全一致，而 `assign` 模式用于赋值场景，允许顶层结构不完全匹配。
5. **处理类型参数的连接 (join):** `join` 方法尝试统一两个类型参数，如果它们已经有不同的推断类型，则连接失败。
6. **处理已绑定和未绑定的类型参数:** 代码区分了已经注册到 `unifier` 的类型参数（已绑定）和未注册的类型参数（未绑定）。
7. **处理接口类型的统一化:** `nify` 方法中包含了对接口类型统一化的特殊处理，包括考虑方法集和类型项 (type terms)。在 `enableInterfaceInference` 开启时，会进行更宽松的接口统一化。
8. **处理各种复合类型的统一化:** 代码针对数组、切片、结构体、指针、元组、函数签名、映射和通道等不同复合类型实现了具体的统一化逻辑。
9. **处理命名类型的统一化:**  当比较命名类型时，会检查它们的声明来源是否相同，并递归地统一它们的类型参数。
10. **处理具有核心类型的未绑定类型参数:** 当 `enableCoreTypeUnification` 启用时，对于未绑定的类型参数，会考虑其约束的核心类型进行统一化。
11. **防止无限递归:**  通过 `unificationDepthLimit` 常量限制递归深度，以避免由于实现问题导致的无限递归。

**推断的 Go 语言功能实现：泛型 (Generics)**

类型统一化是 Go 语言泛型实现的核心机制之一。当 Go 编译器遇到泛型函数或类型时，需要确定类型参数的具体类型。`unify.go` 中的代码正是用于执行这个确定过程，或者说**类型推断 (Type Inference)** 的关键部分。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"go/types"
)

func main() {
	// 假设我们有一个泛型函数，它的类型参数是 T
	// func MyGenericFunc[T any](x T) T { return x }

	// 模拟类型参数
	typeParamT := types.NewTypeParam(0, "T")
	typeParams := []*types.TypeParam{typeParamT}

	// 模拟 unifier
	unifier := types.NewUnifier(typeParams, nil, false)

	// 假设我们调用了这个泛型函数，传入一个 int 类型的值
	concreteType := types.Typ[types.Int]

	// 尝试统一类型参数 T 和 int 类型
	success := unifier.Unify(typeParamT, concreteType, types.Exact)

	fmt.Println("统一化是否成功:", success)
	if success {
		inferredTypes := unifier.Inferred(typeParams)
		fmt.Println("推断出的类型:", inferredTypes) // 输出: 推断出的类型: [int]
	}
}
```

**假设的输入与输出：**

* **输入:**  一个包含单个类型参数 `T` 的 `unifier`，以及要统一的类型参数 `typeParamT` 和具体类型 `concreteType` (例如 `types.Typ[types.Int]`)。
* **输出:**
    * `统一化是否成功: true`
    * `推断出的类型: [int]`

**代码推理：**

1. 创建一个包含类型参数 `T` 的 `unifier`。初始时，`T` 的推断类型是 `nil`。
2. 调用 `unifier.Unify(typeParamT, concreteType, types.Exact)` 尝试将类型参数 `T` 与 `int` 类型进行统一。
3. `unify` 方法会调用 `nify` 方法进行实际的统一化操作。
4. 在 `nify` 方法中，由于 `typeParamT` 是一个已绑定的类型参数，且其当前类型为 `nil`，代码会尝试将其推断为 `concreteType` (`int`)。
5. 如果统一化成功，`unifier` 的内部状态会被更新，`handles` 中 `T` 对应的类型将变为 `int`。
6. 调用 `unifier.Inferred(typeParams)` 可以获取推断出的类型参数的列表，此时 `T` 的类型为 `int`。

**命令行参数的具体处理：**

这段代码本身**没有直接处理命令行参数**。其中定义的 `traceInference` 是一个常量，用于在调试时打印统一化的过程信息，但这需要在编译时修改代码。

在 Go 语言的编译过程中，编译器会使用 `go/types` 包进行类型检查和推断。编译器的实现可能会接收一些与泛型相关的命令行参数（例如控制泛型的行为或启用某些实验性特性），但这些参数的处理逻辑不在 `unify.go` 文件中。

**使用者易犯错的点：**

由于这段代码是 `go/types` 包的内部实现，普通 Go 语言开发者**不会直接使用**它。然而，理解类型统一化的概念对于编写正确的泛型代码至关重要。

在泛型编程中，一些常见的错误可能与类型统一化有关，例如：

1. **类型约束不满足:**  如果泛型类型的类型参数有约束（例如 `[T Number]`），而你尝试用一个不满足该约束的类型（例如 `string`）实例化它，类型统一化会失败。

   ```go
   package main

   import "fmt"

   type Number interface {
       int | float64
   }

   func PrintNumber[T Number](n T) {
       fmt.Println(n)
   }

   func main() {
       // PrintNumber("hello") // 编译错误：string does not implement Number
       PrintNumber(10)
       PrintNumber(3.14)
   }
   ```

2. **类型推断歧义:** 在某些复杂的泛型场景下，编译器可能无法唯一确定类型参数的具体类型，导致类型推断失败。

3. **对类型统一化的理解偏差:** 开发者可能不清楚类型统一化的具体规则，导致对泛型代码的行为产生误解。例如，可能会认为两个结构相同的匿名接口是可以互相替代的，但类型统一化可能仍然会考虑更细微的差异。

总而言之，`go/src/go/types/unify.go` 中的代码是 Go 语言泛型实现的关键组成部分，它负责判断不同类型之间是否兼容，并为泛型类型参数推断出具体的类型。理解其背后的原理有助于更好地理解和使用 Go 语言的泛型功能。

### 提示词
```
这是路径为go/src/go/types/unify.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Code generated by "go test -run=Generate -write=all"; DO NOT EDIT.
// Source: ../../cmd/compile/internal/types2/unify.go

// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements type unification.
//
// Type unification attempts to make two types x and y structurally
// equivalent by determining the types for a given list of (bound)
// type parameters which may occur within x and y. If x and y are
// structurally different (say []T vs chan T), or conflicting
// types are determined for type parameters, unification fails.
// If unification succeeds, as a side-effect, the types of the
// bound type parameters may be determined.
//
// Unification typically requires multiple calls u.unify(x, y) to
// a given unifier u, with various combinations of types x and y.
// In each call, additional type parameter types may be determined
// as a side effect and recorded in u.
// If a call fails (returns false), unification fails.
//
// In the unification context, structural equivalence of two types
// ignores the difference between a defined type and its underlying
// type if one type is a defined type and the other one is not.
// It also ignores the difference between an (external, unbound)
// type parameter and its core type.
// If two types are not structurally equivalent, they cannot be Go
// identical types. On the other hand, if they are structurally
// equivalent, they may be Go identical or at least assignable, or
// they may be in the type set of a constraint.
// Whether they indeed are identical or assignable is determined
// upon instantiation and function argument passing.

package types

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

const (
	// Upper limit for recursion depth. Used to catch infinite recursions
	// due to implementation issues (e.g., see issues go.dev/issue/48619, go.dev/issue/48656).
	unificationDepthLimit = 50

	// Whether to panic when unificationDepthLimit is reached.
	// If disabled, a recursion depth overflow results in a (quiet)
	// unification failure.
	panicAtUnificationDepthLimit = true

	// If enableCoreTypeUnification is set, unification will consider
	// the core types, if any, of non-local (unbound) type parameters.
	enableCoreTypeUnification = true

	// If traceInference is set, unification will print a trace of its operation.
	// Interpretation of trace:
	//   x ≡ y    attempt to unify types x and y
	//   p ➞ y    type parameter p is set to type y (p is inferred to be y)
	//   p ⇄ q    type parameters p and q match (p is inferred to be q and vice versa)
	//   x ≢ y    types x and y cannot be unified
	//   [p, q, ...] ➞ [x, y, ...]    mapping from type parameters to types
	traceInference = false
)

// A unifier maintains a list of type parameters and
// corresponding types inferred for each type parameter.
// A unifier is created by calling newUnifier.
type unifier struct {
	// handles maps each type parameter to its inferred type through
	// an indirection *Type called (inferred type) "handle".
	// Initially, each type parameter has its own, separate handle,
	// with a nil (i.e., not yet inferred) type.
	// After a type parameter P is unified with a type parameter Q,
	// P and Q share the same handle (and thus type). This ensures
	// that inferring the type for a given type parameter P will
	// automatically infer the same type for all other parameters
	// unified (joined) with P.
	handles                  map[*TypeParam]*Type
	depth                    int  // recursion depth during unification
	enableInterfaceInference bool // use shared methods for better inference
}

// newUnifier returns a new unifier initialized with the given type parameter
// and corresponding type argument lists. The type argument list may be shorter
// than the type parameter list, and it may contain nil types. Matching type
// parameters and arguments must have the same index.
func newUnifier(tparams []*TypeParam, targs []Type, enableInterfaceInference bool) *unifier {
	assert(len(tparams) >= len(targs))
	handles := make(map[*TypeParam]*Type, len(tparams))
	// Allocate all handles up-front: in a correct program, all type parameters
	// must be resolved and thus eventually will get a handle.
	// Also, sharing of handles caused by unified type parameters is rare and
	// so it's ok to not optimize for that case (and delay handle allocation).
	for i, x := range tparams {
		var t Type
		if i < len(targs) {
			t = targs[i]
		}
		handles[x] = &t
	}
	return &unifier{handles, 0, enableInterfaceInference}
}

// unifyMode controls the behavior of the unifier.
type unifyMode uint

const (
	// If assign is set, we are unifying types involved in an assignment:
	// they may match inexactly at the top, but element types must match
	// exactly.
	assign unifyMode = 1 << iota

	// If exact is set, types unify if they are identical (or can be
	// made identical with suitable arguments for type parameters).
	// Otherwise, a named type and a type literal unify if their
	// underlying types unify, channel directions are ignored, and
	// if there is an interface, the other type must implement the
	// interface.
	exact
)

func (m unifyMode) String() string {
	switch m {
	case 0:
		return "inexact"
	case assign:
		return "assign"
	case exact:
		return "exact"
	case assign | exact:
		return "assign, exact"
	}
	return fmt.Sprintf("mode %d", m)
}

// unify attempts to unify x and y and reports whether it succeeded.
// As a side-effect, types may be inferred for type parameters.
// The mode parameter controls how types are compared.
func (u *unifier) unify(x, y Type, mode unifyMode) bool {
	return u.nify(x, y, mode, nil)
}

func (u *unifier) tracef(format string, args ...interface{}) {
	fmt.Println(strings.Repeat(".  ", u.depth) + sprintf(nil, nil, true, format, args...))
}

// String returns a string representation of the current mapping
// from type parameters to types.
func (u *unifier) String() string {
	// sort type parameters for reproducible strings
	tparams := make(typeParamsById, len(u.handles))
	i := 0
	for tpar := range u.handles {
		tparams[i] = tpar
		i++
	}
	sort.Sort(tparams)

	var buf bytes.Buffer
	w := newTypeWriter(&buf, nil)
	w.byte('[')
	for i, x := range tparams {
		if i > 0 {
			w.string(", ")
		}
		w.typ(x)
		w.string(": ")
		w.typ(u.at(x))
	}
	w.byte(']')
	return buf.String()
}

type typeParamsById []*TypeParam

func (s typeParamsById) Len() int           { return len(s) }
func (s typeParamsById) Less(i, j int) bool { return s[i].id < s[j].id }
func (s typeParamsById) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

// join unifies the given type parameters x and y.
// If both type parameters already have a type associated with them
// and they are not joined, join fails and returns false.
func (u *unifier) join(x, y *TypeParam) bool {
	if traceInference {
		u.tracef("%s ⇄ %s", x, y)
	}
	switch hx, hy := u.handles[x], u.handles[y]; {
	case hx == hy:
		// Both type parameters already share the same handle. Nothing to do.
	case *hx != nil && *hy != nil:
		// Both type parameters have (possibly different) inferred types. Cannot join.
		return false
	case *hx != nil:
		// Only type parameter x has an inferred type. Use handle of x.
		u.setHandle(y, hx)
	// This case is treated like the default case.
	// case *hy != nil:
	// 	// Only type parameter y has an inferred type. Use handle of y.
	//	u.setHandle(x, hy)
	default:
		// Neither type parameter has an inferred type. Use handle of y.
		u.setHandle(x, hy)
	}
	return true
}

// asBoundTypeParam returns x.(*TypeParam) if x is a type parameter recorded with u.
// Otherwise, the result is nil.
func (u *unifier) asBoundTypeParam(x Type) *TypeParam {
	if x, _ := Unalias(x).(*TypeParam); x != nil {
		if _, found := u.handles[x]; found {
			return x
		}
	}
	return nil
}

// setHandle sets the handle for type parameter x
// (and all its joined type parameters) to h.
func (u *unifier) setHandle(x *TypeParam, h *Type) {
	hx := u.handles[x]
	assert(hx != nil)
	for y, hy := range u.handles {
		if hy == hx {
			u.handles[y] = h
		}
	}
}

// at returns the (possibly nil) type for type parameter x.
func (u *unifier) at(x *TypeParam) Type {
	return *u.handles[x]
}

// set sets the type t for type parameter x;
// t must not be nil.
func (u *unifier) set(x *TypeParam, t Type) {
	assert(t != nil)
	if traceInference {
		u.tracef("%s ➞ %s", x, t)
	}
	*u.handles[x] = t
}

// unknowns returns the number of type parameters for which no type has been set yet.
func (u *unifier) unknowns() int {
	n := 0
	for _, h := range u.handles {
		if *h == nil {
			n++
		}
	}
	return n
}

// inferred returns the list of inferred types for the given type parameter list.
// The result is never nil and has the same length as tparams; result types that
// could not be inferred are nil. Corresponding type parameters and result types
// have identical indices.
func (u *unifier) inferred(tparams []*TypeParam) []Type {
	list := make([]Type, len(tparams))
	for i, x := range tparams {
		list[i] = u.at(x)
	}
	return list
}

// asInterface returns the underlying type of x as an interface if
// it is a non-type parameter interface. Otherwise it returns nil.
func asInterface(x Type) (i *Interface) {
	if _, ok := Unalias(x).(*TypeParam); !ok {
		i, _ = under(x).(*Interface)
	}
	return i
}

// nify implements the core unification algorithm which is an
// adapted version of Checker.identical. For changes to that
// code the corresponding changes should be made here.
// Must not be called directly from outside the unifier.
func (u *unifier) nify(x, y Type, mode unifyMode, p *ifacePair) (result bool) {
	u.depth++
	if traceInference {
		u.tracef("%s ≡ %s\t// %s", x, y, mode)
	}
	defer func() {
		if traceInference && !result {
			u.tracef("%s ≢ %s", x, y)
		}
		u.depth--
	}()

	// nothing to do if x == y
	if x == y || Unalias(x) == Unalias(y) {
		return true
	}

	// Stop gap for cases where unification fails.
	if u.depth > unificationDepthLimit {
		if traceInference {
			u.tracef("depth %d >= %d", u.depth, unificationDepthLimit)
		}
		if panicAtUnificationDepthLimit {
			panic("unification reached recursion depth limit")
		}
		return false
	}

	// Unification is symmetric, so we can swap the operands.
	// Ensure that if we have at least one
	// - defined type, make sure one is in y
	// - type parameter recorded with u, make sure one is in x
	if asNamed(x) != nil || u.asBoundTypeParam(y) != nil {
		if traceInference {
			u.tracef("%s ≡ %s\t// swap", y, x)
		}
		x, y = y, x
	}

	// Unification will fail if we match a defined type against a type literal.
	// If we are matching types in an assignment, at the top-level, types with
	// the same type structure are permitted as long as at least one of them
	// is not a defined type. To accommodate for that possibility, we continue
	// unification with the underlying type of a defined type if the other type
	// is a type literal. This is controlled by the exact unification mode.
	// We also continue if the other type is a basic type because basic types
	// are valid underlying types and may appear as core types of type constraints.
	// If we exclude them, inferred defined types for type parameters may not
	// match against the core types of their constraints (even though they might
	// correctly match against some of the types in the constraint's type set).
	// Finally, if unification (incorrectly) succeeds by matching the underlying
	// type of a defined type against a basic type (because we include basic types
	// as type literals here), and if that leads to an incorrectly inferred type,
	// we will fail at function instantiation or argument assignment time.
	//
	// If we have at least one defined type, there is one in y.
	if ny := asNamed(y); mode&exact == 0 && ny != nil && isTypeLit(x) && !(u.enableInterfaceInference && IsInterface(x)) {
		if traceInference {
			u.tracef("%s ≡ under %s", x, ny)
		}
		y = ny.under()
		// Per the spec, a defined type cannot have an underlying type
		// that is a type parameter.
		assert(!isTypeParam(y))
		// x and y may be identical now
		if x == y || Unalias(x) == Unalias(y) {
			return true
		}
	}

	// Cases where at least one of x or y is a type parameter recorded with u.
	// If we have at least one type parameter, there is one in x.
	// If we have exactly one type parameter, because it is in x,
	// isTypeLit(x) is false and y was not changed above. In other
	// words, if y was a defined type, it is still a defined type
	// (relevant for the logic below).
	switch px, py := u.asBoundTypeParam(x), u.asBoundTypeParam(y); {
	case px != nil && py != nil:
		// both x and y are type parameters
		if u.join(px, py) {
			return true
		}
		// both x and y have an inferred type - they must match
		return u.nify(u.at(px), u.at(py), mode, p)

	case px != nil:
		// x is a type parameter, y is not
		if x := u.at(px); x != nil {
			// x has an inferred type which must match y
			if u.nify(x, y, mode, p) {
				// We have a match, possibly through underlying types.
				xi := asInterface(x)
				yi := asInterface(y)
				xn := asNamed(x) != nil
				yn := asNamed(y) != nil
				// If we have two interfaces, what to do depends on
				// whether they are named and their method sets.
				if xi != nil && yi != nil {
					// Both types are interfaces.
					// If both types are defined types, they must be identical
					// because unification doesn't know which type has the "right" name.
					if xn && yn {
						return Identical(x, y)
					}
					// In all other cases, the method sets must match.
					// The types unified so we know that corresponding methods
					// match and we can simply compare the number of methods.
					// TODO(gri) We may be able to relax this rule and select
					// the more general interface. But if one of them is a defined
					// type, it's not clear how to choose and whether we introduce
					// an order dependency or not. Requiring the same method set
					// is conservative.
					if len(xi.typeSet().methods) != len(yi.typeSet().methods) {
						return false
					}
				} else if xi != nil || yi != nil {
					// One but not both of them are interfaces.
					// In this case, either x or y could be viable matches for the corresponding
					// type parameter, which means choosing either introduces an order dependence.
					// Therefore, we must fail unification (go.dev/issue/60933).
					return false
				}
				// If we have inexact unification and one of x or y is a defined type, select the
				// defined type. This ensures that in a series of types, all matching against the
				// same type parameter, we infer a defined type if there is one, independent of
				// order. Type inference or assignment may fail, which is ok.
				// Selecting a defined type, if any, ensures that we don't lose the type name;
				// and since we have inexact unification, a value of equally named or matching
				// undefined type remains assignable (go.dev/issue/43056).
				//
				// Similarly, if we have inexact unification and there are no defined types but
				// channel types, select a directed channel, if any. This ensures that in a series
				// of unnamed types, all matching against the same type parameter, we infer the
				// directed channel if there is one, independent of order.
				// Selecting a directional channel, if any, ensures that a value of another
				// inexactly unifying channel type remains assignable (go.dev/issue/62157).
				//
				// If we have multiple defined channel types, they are either identical or we
				// have assignment conflicts, so we can ignore directionality in this case.
				//
				// If we have defined and literal channel types, a defined type wins to avoid
				// order dependencies.
				if mode&exact == 0 {
					switch {
					case xn:
						// x is a defined type: nothing to do.
					case yn:
						// x is not a defined type and y is a defined type: select y.
						u.set(px, y)
					default:
						// Neither x nor y are defined types.
						if yc, _ := under(y).(*Chan); yc != nil && yc.dir != SendRecv {
							// y is a directed channel type: select y.
							u.set(px, y)
						}
					}
				}
				return true
			}
			return false
		}
		// otherwise, infer type from y
		u.set(px, y)
		return true
	}

	// x != y if we get here
	assert(x != y && Unalias(x) != Unalias(y))

	// If u.EnableInterfaceInference is set and we don't require exact unification,
	// if both types are interfaces, one interface must have a subset of the
	// methods of the other and corresponding method signatures must unify.
	// If only one type is an interface, all its methods must be present in the
	// other type and corresponding method signatures must unify.
	if u.enableInterfaceInference && mode&exact == 0 {
		// One or both interfaces may be defined types.
		// Look under the name, but not under type parameters (go.dev/issue/60564).
		xi := asInterface(x)
		yi := asInterface(y)
		// If we have two interfaces, check the type terms for equivalence,
		// and unify common methods if possible.
		if xi != nil && yi != nil {
			xset := xi.typeSet()
			yset := yi.typeSet()
			if xset.comparable != yset.comparable {
				return false
			}
			// For now we require terms to be equal.
			// We should be able to relax this as well, eventually.
			if !xset.terms.equal(yset.terms) {
				return false
			}
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
			q := &ifacePair{xi, yi, p}
			for p != nil {
				if p.identical(q) {
					return true // same pair was compared before
				}
				p = p.prev
			}
			// The method set of x must be a subset of the method set
			// of y or vice versa, and the common methods must unify.
			xmethods := xset.methods
			ymethods := yset.methods
			// The smaller method set must be the subset, if it exists.
			if len(xmethods) > len(ymethods) {
				xmethods, ymethods = ymethods, xmethods
			}
			// len(xmethods) <= len(ymethods)
			// Collect the ymethods in a map for quick lookup.
			ymap := make(map[string]*Func, len(ymethods))
			for _, ym := range ymethods {
				ymap[ym.Id()] = ym
			}
			// All xmethods must exist in ymethods and corresponding signatures must unify.
			for _, xm := range xmethods {
				if ym := ymap[xm.Id()]; ym == nil || !u.nify(xm.typ, ym.typ, exact, p) {
					return false
				}
			}
			return true
		}

		// We don't have two interfaces. If we have one, make sure it's in xi.
		if yi != nil {
			xi = yi
			y = x
		}

		// If we have one interface, at a minimum each of the interface methods
		// must be implemented and thus unify with a corresponding method from
		// the non-interface type, otherwise unification fails.
		if xi != nil {
			// All xi methods must exist in y and corresponding signatures must unify.
			xmethods := xi.typeSet().methods
			for _, xm := range xmethods {
				obj, _, _ := LookupFieldOrMethod(y, false, xm.pkg, xm.name)
				if ym, _ := obj.(*Func); ym == nil || !u.nify(xm.typ, ym.typ, exact, p) {
					return false
				}
			}
			return true
		}
	}

	// Unless we have exact unification, neither x nor y are interfaces now.
	// Except for unbound type parameters (see below), x and y must be structurally
	// equivalent to unify.

	// If we get here and x or y is a type parameter, they are unbound
	// (not recorded with the unifier).
	// Ensure that if we have at least one type parameter, it is in x
	// (the earlier swap checks for _recorded_ type parameters only).
	// This ensures that the switch switches on the type parameter.
	//
	// TODO(gri) Factor out type parameter handling from the switch.
	if isTypeParam(y) {
		if traceInference {
			u.tracef("%s ≡ %s\t// swap", y, x)
		}
		x, y = y, x
	}

	// Type elements (array, slice, etc. elements) use emode for unification.
	// Element types must match exactly if the types are used in an assignment.
	emode := mode
	if mode&assign != 0 {
		emode |= exact
	}

	// Continue with unaliased types but don't lose original alias names, if any (go.dev/issue/67628).
	xorig, x := x, Unalias(x)
	yorig, y := y, Unalias(y)

	switch x := x.(type) {
	case *Basic:
		// Basic types are singletons except for the rune and byte
		// aliases, thus we cannot solely rely on the x == y check
		// above. See also comment in TypeName.IsAlias.
		if y, ok := y.(*Basic); ok {
			return x.kind == y.kind
		}

	case *Array:
		// Two array types unify if they have the same array length
		// and their element types unify.
		if y, ok := y.(*Array); ok {
			// If one or both array lengths are unknown (< 0) due to some error,
			// assume they are the same to avoid spurious follow-on errors.
			return (x.len < 0 || y.len < 0 || x.len == y.len) && u.nify(x.elem, y.elem, emode, p)
		}

	case *Slice:
		// Two slice types unify if their element types unify.
		if y, ok := y.(*Slice); ok {
			return u.nify(x.elem, y.elem, emode, p)
		}

	case *Struct:
		// Two struct types unify if they have the same sequence of fields,
		// and if corresponding fields have the same names, their (field) types unify,
		// and they have identical tags. Two embedded fields are considered to have the same
		// name. Lower-case field names from different packages are always different.
		if y, ok := y.(*Struct); ok {
			if x.NumFields() == y.NumFields() {
				for i, f := range x.fields {
					g := y.fields[i]
					if f.embedded != g.embedded ||
						x.Tag(i) != y.Tag(i) ||
						!f.sameId(g.pkg, g.name, false) ||
						!u.nify(f.typ, g.typ, emode, p) {
						return false
					}
				}
				return true
			}
		}

	case *Pointer:
		// Two pointer types unify if their base types unify.
		if y, ok := y.(*Pointer); ok {
			return u.nify(x.base, y.base, emode, p)
		}

	case *Tuple:
		// Two tuples types unify if they have the same number of elements
		// and the types of corresponding elements unify.
		if y, ok := y.(*Tuple); ok {
			if x.Len() == y.Len() {
				if x != nil {
					for i, v := range x.vars {
						w := y.vars[i]
						if !u.nify(v.typ, w.typ, mode, p) {
							return false
						}
					}
				}
				return true
			}
		}

	case *Signature:
		// Two function types unify if they have the same number of parameters
		// and result values, corresponding parameter and result types unify,
		// and either both functions are variadic or neither is.
		// Parameter and result names are not required to match.
		// TODO(gri) handle type parameters or document why we can ignore them.
		if y, ok := y.(*Signature); ok {
			return x.variadic == y.variadic &&
				u.nify(x.params, y.params, emode, p) &&
				u.nify(x.results, y.results, emode, p)
		}

	case *Interface:
		assert(!u.enableInterfaceInference || mode&exact != 0) // handled before this switch

		// Two interface types unify if they have the same set of methods with
		// the same names, and corresponding function types unify.
		// Lower-case method names from different packages are always different.
		// The order of the methods is irrelevant.
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
					if f.Id() != g.Id() || !u.nify(f.typ, g.typ, exact, q) {
						return false
					}
				}
				return true
			}
		}

	case *Map:
		// Two map types unify if their key and value types unify.
		if y, ok := y.(*Map); ok {
			return u.nify(x.key, y.key, emode, p) && u.nify(x.elem, y.elem, emode, p)
		}

	case *Chan:
		// Two channel types unify if their value types unify
		// and if they have the same direction.
		// The channel direction is ignored for inexact unification.
		if y, ok := y.(*Chan); ok {
			return (mode&exact == 0 || x.dir == y.dir) && u.nify(x.elem, y.elem, emode, p)
		}

	case *Named:
		// Two named types unify if their type names originate in the same type declaration.
		// If they are instantiated, their type argument lists must unify.
		if y := asNamed(y); y != nil {
			// Check type arguments before origins so they unify
			// even if the origins don't match; for better error
			// messages (see go.dev/issue/53692).
			xargs := x.TypeArgs().list()
			yargs := y.TypeArgs().list()
			if len(xargs) != len(yargs) {
				return false
			}
			for i, xarg := range xargs {
				if !u.nify(xarg, yargs[i], mode, p) {
					return false
				}
			}
			return identicalOrigin(x, y)
		}

	case *TypeParam:
		// x must be an unbound type parameter (see comment above).
		if debug {
			assert(u.asBoundTypeParam(x) == nil)
		}
		// By definition, a valid type argument must be in the type set of
		// the respective type constraint. Therefore, the type argument's
		// underlying type must be in the set of underlying types of that
		// constraint. If there is a single such underlying type, it's the
		// constraint's core type. It must match the type argument's under-
		// lying type, irrespective of whether the actual type argument,
		// which may be a defined type, is actually in the type set (that
		// will be determined at instantiation time).
		// Thus, if we have the core type of an unbound type parameter,
		// we know the structure of the possible types satisfying such
		// parameters. Use that core type for further unification
		// (see go.dev/issue/50755 for a test case).
		if enableCoreTypeUnification {
			// Because the core type is always an underlying type,
			// unification will take care of matching against a
			// defined or literal type automatically.
			// If y is also an unbound type parameter, we will end
			// up here again with x and y swapped, so we don't
			// need to take care of that case separately.
			if cx := coreType(x); cx != nil {
				if traceInference {
					u.tracef("core %s ≡ %s", xorig, yorig)
				}
				// If y is a defined type, it may not match against cx which
				// is an underlying type (incl. int, string, etc.). Use assign
				// mode here so that the unifier automatically takes under(y)
				// if necessary.
				return u.nify(cx, yorig, assign, p)
			}
		}
		// x != y and there's nothing to do

	case nil:
		// avoid a crash in case of nil type

	default:
		panic(sprintf(nil, nil, true, "u.nify(%s, %s, %d)", xorig, yorig, mode))
	}

	return false
}
```