Response: My thinking process to answer the request about `named.go` goes like this:

1. **Understand the Goal:** The user wants to know the functionality of the `named.go` file in the Go compiler's `types2` package. They also want code examples and explanations related to Go language features implemented by this file.

2. **Initial Skim for Keywords and Concepts:** I'll quickly scan the code for prominent terms and comments. Keywords like "Named types," "LHS," "RHS," "instantiated," "declared," "resolved," "expanded," "generic," "type parameters," "type arguments," "methods," and "underlying type" immediately stand out. The comments explicitly explain the core concepts.

3. **Identify the Core Functionality:** The comments clearly state that `named.go` handles the type-checking of named types, especially the complexities arising from recursion, multiple declarations (for methods), and the need for lazy evaluation. The "LHS" and "RHS" distinction is key to understanding the delayed availability of certain type information.

4. **Connect to Go Language Features:**  Based on the keywords and concepts, I can identify the related Go language features:
    * **Named Types:** This is fundamental and the file's namesake. Examples: `type MyInt int`, `type MyStruct struct { ... }`.
    * **Generic Types:** The mentions of "generic," "type parameters," and "instantiated" strongly suggest this. Examples: `type MyGeneric[T any] struct { value T }`, `type MyInstance = MyGeneric[int]`.
    * **Methods on Types:** The discussion about methods and their lazy checking points to this feature. Examples: `func (m MyStruct) MyMethod() {}`.
    * **Type Aliases:** While mentioned in a comment as a pre-Go 1.9 term, it's not the core focus.
    * **Recursive Types:** The comments explicitly mention the subtlety of handling recursively defined types. Example: `type Node struct { Next *Node }`.

5. **Structure the Explanation:** I'll organize the explanation based on the user's request, covering:
    * **Functionality:** A high-level summary of what `named.go` does.
    * **Go Language Feature Implementation:** Connecting the code to specific Go features with examples.
    * **Code Inference (with Assumptions):**  Illustrating how the code manages different states and operations with hypothetical input and output.
    * **Command-Line Arguments:** Since this file is part of the compiler's internal workings, it doesn't directly handle command-line arguments. I need to explain this.
    * **Common Mistakes:**  Identifying potential pitfalls for users.

6. **Develop Code Examples:** For each identified Go feature, I'll create simple, illustrative code snippets. These examples should demonstrate the concepts discussed in the comments and code.

7. **Simulate Code Inference:**  I'll pick a specific aspect of the code, like the state transitions or method expansion, and create a scenario with a hypothetical input (e.g., a generic type instantiation) and trace the expected "output" or state changes based on the code's logic. I need to make reasonable assumptions about the internal state.

8. **Address Command-Line Arguments:** I need to explicitly state that `named.go` is an internal component and doesn't directly process command-line arguments. The overall compiler driver (like `go build`) handles those.

9. **Identify Common Mistakes:** This requires some understanding of how developers might misuse or misunderstand the features related to named types, generics, and methods. Examples include:
    * Trying to use incomplete types.
    * Incorrectly instantiating generic types.
    * Issues with recursive type definitions.

10. **Review and Refine:**  Finally, I'll review the entire explanation to ensure clarity, accuracy, and completeness. I'll check for any inconsistencies or areas where more detail might be helpful. I will also make sure the code examples compile and accurately demonstrate the intended points.

By following these steps, I can construct a comprehensive and informative answer that addresses all aspects of the user's request. The key is to understand the high-level purpose of the file, connect it to relevant Go language features, and then illustrate these connections with concrete examples and explanations.
`go/src/cmd/compile/internal/types2/named.go` 文件的主要功能是处理 Go 语言中命名类型（named types）的类型检查和相关操作。由于命名类型可能存在递归定义，并且其完整信息可能分布在多个声明中（通过方法），因此其类型检查非常微妙。该文件通过延迟加载和并发控制等机制来管理这些复杂性。

以下是 `named.go` 的主要功能：

1. **表示命名类型:** `Named` 结构体是该文件的核心，它用于表示 Go 语言中的命名类型，例如通过 `type MyInt int` 或 `type MyStruct struct { ... }` 定义的类型。它包含了类型名称 (`TypeName`)、底层类型 (`underlying`)、类型参数 (`TypeParams`) 和方法 (`methods`) 等信息。

2. **延迟类型检查:**  `named.go` 实现了命名类型的延迟类型检查。这意味着在首次需要某个命名类型的完整信息时，才会去解析其底层类型和方法。这对于处理递归类型定义至关重要，可以避免无限循环。

3. **管理命名类型的状态:**  使用原子变量 `state_` 来跟踪命名类型的状态，例如 `unresolved`（未解析）、`resolved`（已解析，但方法可能不完整）和 `complete`（所有信息已知）。这有助于在并发访问时保证数据的一致性。

4. **处理泛型类型的实例化:**  `named.go` 负责处理泛型类型的实例化。当一个泛型类型被实例化时（例如 `MyGeneric[int]`），会创建一个新的 `Named` 实例，其中包含原始泛型类型 (`orig`) 和类型参数 (`targs`) 等信息。

5. **方法管理:** 维护命名类型的方法列表。对于非泛型类型，该列表在类型检查时完全填充。对于泛型类型的实例，方法是按需扩展的，即在首次访问时才会进行类型参数替换。

6. **从导出数据加载信息:**  支持从导出数据中加载命名类型的信息，包括类型参数、底层类型和方法。这可以通过 `loader` 函数实现延迟加载。

7. **处理递归类型:** 通过在类型检查过程中提前分配 `Named` 对象，即使其底层类型或方法尚未完全确定，也能解决递归引用的问题。

8. **并发控制:** 使用互斥锁 `mu` 来保护可能并发访问的字段，确保在多线程环境下的数据安全。

**Go 语言功能实现示例：**

**1. 定义和使用命名类型：**

```go
package main

type MyInt int

func main() {
	var x MyInt = 10
	println(x)
}
```

在类型检查阶段，`named.go` 会创建 `MyInt` 类型的 `Named` 结构体，并将其底层类型设置为 `int`。

**2. 泛型类型的定义和实例化：**

```go
package main

type MyGeneric[T any] struct {
	value T
}

func main() {
	var instance MyGeneric[int]
	instance.value = 10
	println(instance.value)

	var instance2 MyGeneric[string]
	instance2.value = "hello"
	println(instance2.value)
}
```

当编译器遇到 `MyGeneric[int]` 和 `MyGeneric[string]` 时，`named.go` 会分别创建 `MyGeneric[int]` 和 `MyGeneric[string]` 两个 `Named` 实例。这些实例会记录原始的泛型类型 `MyGeneric` 和相应的类型参数 `int` 和 `string`。

**3. 带有方法的命名类型：**

```go
package main

type MyStruct struct {
	value int
}

func (s MyStruct) GetValue() int {
	return s.value
}

func main() {
	s := MyStruct{value: 5}
	println(s.GetValue())
}
```

`named.go` 会将 `GetValue` 方法与 `MyStruct` 类型的 `Named` 结构体关联起来。

**代码推理（假设）：**

**假设输入：** 正在类型检查以下代码：

```go
package main

type A struct {
	b *B
}

type B struct {
	a *A
}

func main() {
	var x A
	println(x)
}
```

**推理过程：**

1. 当类型检查器遇到 `type A struct { b *B }` 时，`named.go` 会为 `A` 创建一个 `Named` 结构体，此时 `A` 的状态是 `unresolved`，底层类型是结构体，但其字段 `b` 的类型 `*B` 尚未完全解析。

2. 接着，类型检查器遇到 `type B struct { a *A }`，`named.go` 会为 `B` 创建一个 `Named` 结构体，状态也是 `unresolved`，字段 `a` 的类型 `*A` 也尚未完全解析。

3. 当需要访问 `A` 或 `B` 的完整信息时（例如，在 `main` 函数中声明变量 `x A`），`named.go` 会尝试解析它们的底层类型。由于 `A` 的字段引用了 `B`，而 `B` 的字段又引用了 `A`，存在循环依赖。

4. `named.go` 通过维护已遇到的类型集合来检测这种循环依赖。当尝试解析 `A` 的底层类型时，会发现需要先解析 `B`，而在解析 `B` 的过程中又会尝试解析 `A`，从而检测到循环。

**假设输出：**  类型检查器会报告一个循环依赖错误，类似于：`type check cycle in declaration of A`。

**命令行参数处理：**

`named.go` 是 `go` 编译器的内部组成部分，它本身不直接处理命令行参数。命令行参数的处理是由 `go` 命令及其子命令（如 `go build`, `go run` 等）负责的。这些命令会解析命令行参数，并调用编译器进行代码的编译和类型检查。`named.go` 作为类型检查器的一部分，会接收由上层模块传递过来的类型信息和上下文。

**使用者易犯错的点：**

1. **尝试使用未完全定义的类型：**  在复杂的类型定义中，特别是涉及递归或相互引用的类型时，可能会出现尝试访问尚未完全解析的类型信息的错误。编译器会通过延迟加载和状态管理来避免这种情况，但在某些极端情况下，可能会出现意想不到的行为。

2. **在泛型实例化时提供错误的类型参数：**  如果提供的类型参数与泛型类型的类型参数约束不匹配，会导致编译错误。例如，如果一个泛型函数要求类型参数实现某个接口，但实际提供的类型参数没有实现该接口。

   ```go
   package main

   type Stringer interface {
       String() string
   }

   type MyGeneric[T Stringer] struct {
       value T
   }

   type MyInt int

   func main() {
       // 错误：MyInt 没有 String() 方法
       // var instance MyGeneric[MyInt]
   }
   ```

3. **忽略类型别名的底层类型：**  虽然类型别名在语法上看起来像是新的类型，但它们与底层类型共享相同的类型。这可能会导致一些混淆，特别是在方法集方面。

   ```go
   package main

   type MyIntAlias = int

   func (i MyIntAlias) Double() MyIntAlias {
       return i * 2
   }

   func main() {
       var x int = 5
       // 可以直接将 int 类型的值赋给 MyIntAlias，因为它们底层类型相同
       var y MyIntAlias = x
       println(y.Double()) // 可以调用 MyIntAlias 上定义的方法
   }
   ```

总而言之，`go/src/cmd/compile/internal/types2/named.go` 是 Go 语言类型系统中一个至关重要的组成部分，它负责管理和类型检查命名类型，特别是处理泛型和递归类型等复杂情况，确保 Go 代码的类型安全性。用户通常不需要直接与这个文件交互，但理解其背后的机制有助于更好地理解 Go 语言的类型系统。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/types2/named.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package types2

import (
	"cmd/compile/internal/syntax"
	"strings"
	"sync"
	"sync/atomic"
)

// Type-checking Named types is subtle, because they may be recursively
// defined, and because their full details may be spread across multiple
// declarations (via methods). For this reason they are type-checked lazily,
// to avoid information being accessed before it is complete.
//
// Conceptually, it is helpful to think of named types as having two distinct
// sets of information:
//  - "LHS" information, defining their identity: Obj() and TypeArgs()
//  - "RHS" information, defining their details: TypeParams(), Underlying(),
//    and methods.
//
// In this taxonomy, LHS information is available immediately, but RHS
// information is lazy. Specifically, a named type N may be constructed in any
// of the following ways:
//  1. type-checked from the source
//  2. loaded eagerly from export data
//  3. loaded lazily from export data (when using unified IR)
//  4. instantiated from a generic type
//
// In cases 1, 3, and 4, it is possible that the underlying type or methods of
// N may not be immediately available.
//  - During type-checking, we allocate N before type-checking its underlying
//    type or methods, so that we may resolve recursive references.
//  - When loading from export data, we may load its methods and underlying
//    type lazily using a provided load function.
//  - After instantiating, we lazily expand the underlying type and methods
//    (note that instances may be created while still in the process of
//    type-checking the original type declaration).
//
// In cases 3 and 4 this lazy construction may also occur concurrently, due to
// concurrent use of the type checker API (after type checking or importing has
// finished). It is critical that we keep track of state, so that Named types
// are constructed exactly once and so that we do not access their details too
// soon.
//
// We achieve this by tracking state with an atomic state variable, and
// guarding potentially concurrent calculations with a mutex. At any point in
// time this state variable determines which data on N may be accessed. As
// state monotonically progresses, any data available at state M may be
// accessed without acquiring the mutex at state N, provided N >= M.
//
// GLOSSARY: Here are a few terms used in this file to describe Named types:
//  - We say that a Named type is "instantiated" if it has been constructed by
//    instantiating a generic named type with type arguments.
//  - We say that a Named type is "declared" if it corresponds to a type
//    declaration in the source. Instantiated named types correspond to a type
//    instantiation in the source, not a declaration. But their Origin type is
//    a declared type.
//  - We say that a Named type is "resolved" if its RHS information has been
//    loaded or fully type-checked. For Named types constructed from export
//    data, this may involve invoking a loader function to extract information
//    from export data. For instantiated named types this involves reading
//    information from their origin.
//  - We say that a Named type is "expanded" if it is an instantiated type and
//    type parameters in its underlying type and methods have been substituted
//    with the type arguments from the instantiation. A type may be partially
//    expanded if some but not all of these details have been substituted.
//    Similarly, we refer to these individual details (underlying type or
//    method) as being "expanded".
//  - When all information is known for a named type, we say it is "complete".
//
// Some invariants to keep in mind: each declared Named type has a single
// corresponding object, and that object's type is the (possibly generic) Named
// type. Declared Named types are identical if and only if their pointers are
// identical. On the other hand, multiple instantiated Named types may be
// identical even though their pointers are not identical. One has to use
// Identical to compare them. For instantiated named types, their obj is a
// synthetic placeholder that records their position of the corresponding
// instantiation in the source (if they were constructed during type checking).
//
// To prevent infinite expansion of named instances that are created outside of
// type-checking, instances share a Context with other instances created during
// their expansion. Via the pidgeonhole principle, this guarantees that in the
// presence of a cycle of named types, expansion will eventually find an
// existing instance in the Context and short-circuit the expansion.
//
// Once an instance is complete, we can nil out this shared Context to unpin
// memory, though this Context may still be held by other incomplete instances
// in its "lineage".

// A Named represents a named (defined) type.
//
// A declaration such as:
//
//	type S struct { ... }
//
// creates a defined type whose underlying type is a struct,
// and binds this type to the object S, a [TypeName].
// Use [Named.Underlying] to access the underlying type.
// Use [Named.Obj] to obtain the object S.
//
// Before type aliases (Go 1.9), the spec called defined types "named types".
type Named struct {
	check *Checker  // non-nil during type-checking; nil otherwise
	obj   *TypeName // corresponding declared object for declared types; see above for instantiated types

	// fromRHS holds the type (on RHS of declaration) this *Named type is derived
	// from (for cycle reporting). Only used by validType, and therefore does not
	// require synchronization.
	fromRHS Type

	// information for instantiated types; nil otherwise
	inst *instance

	mu         sync.Mutex     // guards all fields below
	state_     uint32         // the current state of this type; must only be accessed atomically
	underlying Type           // possibly a *Named during setup; never a *Named once set up completely
	tparams    *TypeParamList // type parameters, or nil

	// methods declared for this type (not the method set of this type)
	// Signatures are type-checked lazily.
	// For non-instantiated types, this is a fully populated list of methods. For
	// instantiated types, methods are individually expanded when they are first
	// accessed.
	methods []*Func

	// loader may be provided to lazily load type parameters, underlying type, and methods.
	loader func(*Named) (tparams []*TypeParam, underlying Type, methods []*Func)
}

// instance holds information that is only necessary for instantiated named
// types.
type instance struct {
	orig            *Named    // original, uninstantiated type
	targs           *TypeList // type arguments
	expandedMethods int       // number of expanded methods; expandedMethods <= len(orig.methods)
	ctxt            *Context  // local Context; set to nil after full expansion
}

// namedState represents the possible states that a named type may assume.
type namedState uint32

const (
	unresolved namedState = iota // tparams, underlying type and methods might be unavailable
	resolved                     // resolve has run; methods might be incomplete (for instances)
	complete                     // all data is known
)

// NewNamed returns a new named type for the given type name, underlying type, and associated methods.
// If the given type name obj doesn't have a type yet, its type is set to the returned named type.
// The underlying type must not be a *Named.
func NewNamed(obj *TypeName, underlying Type, methods []*Func) *Named {
	if asNamed(underlying) != nil {
		panic("underlying type must not be *Named")
	}
	return (*Checker)(nil).newNamed(obj, underlying, methods)
}

// resolve resolves the type parameters, methods, and underlying type of n.
// This information may be loaded from a provided loader function, or computed
// from an origin type (in the case of instances).
//
// After resolution, the type parameters, methods, and underlying type of n are
// accessible; but if n is an instantiated type, its methods may still be
// unexpanded.
func (n *Named) resolve() *Named {
	if n.state() >= resolved { // avoid locking below
		return n
	}

	// TODO(rfindley): if n.check is non-nil we can avoid locking here, since
	// type-checking is not concurrent. Evaluate if this is worth doing.
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.state() >= resolved {
		return n
	}

	if n.inst != nil {
		assert(n.underlying == nil) // n is an unresolved instance
		assert(n.loader == nil)     // instances are created by instantiation, in which case n.loader is nil

		orig := n.inst.orig
		orig.resolve()
		underlying := n.expandUnderlying()

		n.tparams = orig.tparams
		n.underlying = underlying
		n.fromRHS = orig.fromRHS // for cycle detection

		if len(orig.methods) == 0 {
			n.setState(complete) // nothing further to do
			n.inst.ctxt = nil
		} else {
			n.setState(resolved)
		}
		return n
	}

	// TODO(mdempsky): Since we're passing n to the loader anyway
	// (necessary because types2 expects the receiver type for methods
	// on defined interface types to be the Named rather than the
	// underlying Interface), maybe it should just handle calling
	// SetTypeParams, SetUnderlying, and AddMethod instead?  Those
	// methods would need to support reentrant calls though. It would
	// also make the API more future-proof towards further extensions.
	if n.loader != nil {
		assert(n.underlying == nil)
		assert(n.TypeArgs().Len() == 0) // instances are created by instantiation, in which case n.loader is nil

		tparams, underlying, methods := n.loader(n)

		n.tparams = bindTParams(tparams)
		n.underlying = underlying
		n.fromRHS = underlying // for cycle detection
		n.methods = methods
		n.loader = nil
	}

	n.setState(complete)
	return n
}

// state atomically accesses the current state of the receiver.
func (n *Named) state() namedState {
	return namedState(atomic.LoadUint32(&n.state_))
}

// setState atomically stores the given state for n.
// Must only be called while holding n.mu.
func (n *Named) setState(state namedState) {
	atomic.StoreUint32(&n.state_, uint32(state))
}

// newNamed is like NewNamed but with a *Checker receiver.
func (check *Checker) newNamed(obj *TypeName, underlying Type, methods []*Func) *Named {
	typ := &Named{check: check, obj: obj, fromRHS: underlying, underlying: underlying, methods: methods}
	if obj.typ == nil {
		obj.typ = typ
	}
	// Ensure that typ is always sanity-checked.
	if check != nil {
		check.needsCleanup(typ)
	}
	return typ
}

// newNamedInstance creates a new named instance for the given origin and type
// arguments, recording pos as the position of its synthetic object (for error
// reporting).
//
// If set, expanding is the named type instance currently being expanded, that
// led to the creation of this instance.
func (check *Checker) newNamedInstance(pos syntax.Pos, orig *Named, targs []Type, expanding *Named) *Named {
	assert(len(targs) > 0)

	obj := NewTypeName(pos, orig.obj.pkg, orig.obj.name, nil)
	inst := &instance{orig: orig, targs: newTypeList(targs)}

	// Only pass the expanding context to the new instance if their packages
	// match. Since type reference cycles are only possible within a single
	// package, this is sufficient for the purposes of short-circuiting cycles.
	// Avoiding passing the context in other cases prevents unnecessary coupling
	// of types across packages.
	if expanding != nil && expanding.Obj().pkg == obj.pkg {
		inst.ctxt = expanding.inst.ctxt
	}
	typ := &Named{check: check, obj: obj, inst: inst}
	obj.typ = typ
	// Ensure that typ is always sanity-checked.
	if check != nil {
		check.needsCleanup(typ)
	}
	return typ
}

func (t *Named) cleanup() {
	assert(t.inst == nil || t.inst.orig.inst == nil)
	// Ensure that every defined type created in the course of type-checking has
	// either non-*Named underlying type, or is unexpanded.
	//
	// This guarantees that we don't leak any types whose underlying type is
	// *Named, because any unexpanded instances will lazily compute their
	// underlying type by substituting in the underlying type of their origin.
	// The origin must have either been imported or type-checked and expanded
	// here, and in either case its underlying type will be fully expanded.
	switch t.underlying.(type) {
	case nil:
		if t.TypeArgs().Len() == 0 {
			panic("nil underlying")
		}
	case *Named, *Alias:
		t.under() // t.under may add entries to check.cleaners
	}
	t.check = nil
}

// Obj returns the type name for the declaration defining the named type t. For
// instantiated types, this is same as the type name of the origin type.
func (t *Named) Obj() *TypeName {
	if t.inst == nil {
		return t.obj
	}
	return t.inst.orig.obj
}

// Origin returns the generic type from which the named type t is
// instantiated. If t is not an instantiated type, the result is t.
func (t *Named) Origin() *Named {
	if t.inst == nil {
		return t
	}
	return t.inst.orig
}

// TypeParams returns the type parameters of the named type t, or nil.
// The result is non-nil for an (originally) generic type even if it is instantiated.
func (t *Named) TypeParams() *TypeParamList { return t.resolve().tparams }

// SetTypeParams sets the type parameters of the named type t.
// t must not have type arguments.
func (t *Named) SetTypeParams(tparams []*TypeParam) {
	assert(t.inst == nil)
	t.resolve().tparams = bindTParams(tparams)
}

// TypeArgs returns the type arguments used to instantiate the named type t.
func (t *Named) TypeArgs() *TypeList {
	if t.inst == nil {
		return nil
	}
	return t.inst.targs
}

// NumMethods returns the number of explicit methods defined for t.
func (t *Named) NumMethods() int {
	return len(t.Origin().resolve().methods)
}

// Method returns the i'th method of named type t for 0 <= i < t.NumMethods().
//
// For an ordinary or instantiated type t, the receiver base type of this
// method is the named type t. For an uninstantiated generic type t, each
// method receiver is instantiated with its receiver type parameters.
//
// Methods are numbered deterministically: given the same list of source files
// presented to the type checker, or the same sequence of NewMethod and AddMethod
// calls, the mapping from method index to corresponding method remains the same.
// But the specific ordering is not specified and must not be relied on as it may
// change in the future.
func (t *Named) Method(i int) *Func {
	t.resolve()

	if t.state() >= complete {
		return t.methods[i]
	}

	assert(t.inst != nil) // only instances should have incomplete methods
	orig := t.inst.orig

	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.methods) != len(orig.methods) {
		assert(len(t.methods) == 0)
		t.methods = make([]*Func, len(orig.methods))
	}

	if t.methods[i] == nil {
		assert(t.inst.ctxt != nil) // we should still have a context remaining from the resolution phase
		t.methods[i] = t.expandMethod(i)
		t.inst.expandedMethods++

		// Check if we've created all methods at this point. If we have, mark the
		// type as fully expanded.
		if t.inst.expandedMethods == len(orig.methods) {
			t.setState(complete)
			t.inst.ctxt = nil // no need for a context anymore
		}
	}

	return t.methods[i]
}

// expandMethod substitutes type arguments in the i'th method for an
// instantiated receiver.
func (t *Named) expandMethod(i int) *Func {
	// t.orig.methods is not lazy. origm is the method instantiated with its
	// receiver type parameters (the "origin" method).
	origm := t.inst.orig.Method(i)
	assert(origm != nil)

	check := t.check
	// Ensure that the original method is type-checked.
	if check != nil {
		check.objDecl(origm, nil)
	}

	origSig := origm.typ.(*Signature)
	rbase, _ := deref(origSig.Recv().Type())

	// If rbase is t, then origm is already the instantiated method we're looking
	// for. In this case, we return origm to preserve the invariant that
	// traversing Method->Receiver Type->Method should get back to the same
	// method.
	//
	// This occurs if t is instantiated with the receiver type parameters, as in
	// the use of m in func (r T[_]) m() { r.m() }.
	if rbase == t {
		return origm
	}

	sig := origSig
	// We can only substitute if we have a correspondence between type arguments
	// and type parameters. This check is necessary in the presence of invalid
	// code.
	if origSig.RecvTypeParams().Len() == t.inst.targs.Len() {
		smap := makeSubstMap(origSig.RecvTypeParams().list(), t.inst.targs.list())
		var ctxt *Context
		if check != nil {
			ctxt = check.context()
		}
		sig = check.subst(origm.pos, origSig, smap, t, ctxt).(*Signature)
	}

	if sig == origSig {
		// No substitution occurred, but we still need to create a new signature to
		// hold the instantiated receiver.
		copy := *origSig
		sig = &copy
	}

	var rtyp Type
	if origm.hasPtrRecv() {
		rtyp = NewPointer(t)
	} else {
		rtyp = t
	}

	sig.recv = cloneVar(origSig.recv, rtyp)
	return cloneFunc(origm, sig)
}

// SetUnderlying sets the underlying type and marks t as complete.
// t must not have type arguments.
func (t *Named) SetUnderlying(underlying Type) {
	assert(t.inst == nil)
	if underlying == nil {
		panic("underlying type must not be nil")
	}
	if asNamed(underlying) != nil {
		panic("underlying type must not be *Named")
	}
	t.resolve().underlying = underlying
	if t.fromRHS == nil {
		t.fromRHS = underlying // for cycle detection
	}
}

// AddMethod adds method m unless it is already in the method list.
// The method must be in the same package as t, and t must not have
// type arguments.
func (t *Named) AddMethod(m *Func) {
	assert(samePkg(t.obj.pkg, m.pkg))
	assert(t.inst == nil)
	t.resolve()
	if t.methodIndex(m.name, false) < 0 {
		t.methods = append(t.methods, m)
	}
}

// methodIndex returns the index of the method with the given name.
// If foldCase is set, capitalization in the name is ignored.
// The result is negative if no such method exists.
func (t *Named) methodIndex(name string, foldCase bool) int {
	if name == "_" {
		return -1
	}
	if foldCase {
		for i, m := range t.methods {
			if strings.EqualFold(m.name, name) {
				return i
			}
		}
	} else {
		for i, m := range t.methods {
			if m.name == name {
				return i
			}
		}
	}
	return -1
}

// Underlying returns the [underlying type] of the named type t, resolving all
// forwarding declarations. Underlying types are never Named, TypeParam, or
// Alias types.
//
// [underlying type]: https://go.dev/ref/spec#Underlying_types.
func (t *Named) Underlying() Type {
	// TODO(gri) Investigate if Unalias can be moved to where underlying is set.
	return Unalias(t.resolve().underlying)
}

func (t *Named) String() string { return TypeString(t, nil) }

// ----------------------------------------------------------------------------
// Implementation
//
// TODO(rfindley): reorganize the loading and expansion methods under this
// heading.

// under returns the expanded underlying type of n0; possibly by following
// forward chains of named types. If an underlying type is found, resolve
// the chain by setting the underlying type for each defined type in the
// chain before returning it. If no underlying type is found or a cycle
// is detected, the result is Typ[Invalid]. If a cycle is detected and
// n0.check != nil, the cycle is reported.
//
// This is necessary because the underlying type of named may be itself a
// named type that is incomplete:
//
//	type (
//		A B
//		B *C
//		C A
//	)
//
// The type of C is the (named) type of A which is incomplete,
// and which has as its underlying type the named type B.
func (n0 *Named) under() Type {
	u := n0.Underlying()

	// If the underlying type of a defined type is not a defined
	// (incl. instance) type, then that is the desired underlying
	// type.
	var n1 *Named
	switch u1 := u.(type) {
	case nil:
		// After expansion via Underlying(), we should never encounter a nil
		// underlying.
		panic("nil underlying")
	default:
		// common case
		return u
	case *Named:
		// handled below
		n1 = u1
	}

	if n0.check == nil {
		panic("Named.check == nil but type is incomplete")
	}

	// Invariant: after this point n0 as well as any named types in its
	// underlying chain should be set up when this function exits.
	check := n0.check
	n := n0

	seen := make(map[*Named]int) // types that need their underlying type resolved
	var path []Object            // objects encountered, for cycle reporting

loop:
	for {
		seen[n] = len(seen)
		path = append(path, n.obj)
		n = n1
		if i, ok := seen[n]; ok {
			// cycle
			check.cycleError(path[i:], firstInSrc(path[i:]))
			u = Typ[Invalid]
			break
		}
		u = n.Underlying()
		switch u1 := u.(type) {
		case nil:
			u = Typ[Invalid]
			break loop
		default:
			break loop
		case *Named:
			// Continue collecting *Named types in the chain.
			n1 = u1
		}
	}

	for n := range seen {
		// We should never have to update the underlying type of an imported type;
		// those underlying types should have been resolved during the import.
		// Also, doing so would lead to a race condition (was go.dev/issue/31749).
		// Do this check always, not just in debug mode (it's cheap).
		if n.obj.pkg != check.pkg {
			panic("imported type with unresolved underlying type")
		}
		n.underlying = u
	}

	return u
}

func (n *Named) lookupMethod(pkg *Package, name string, foldCase bool) (int, *Func) {
	n.resolve()
	if samePkg(n.obj.pkg, pkg) || isExported(name) || foldCase {
		// If n is an instance, we may not have yet instantiated all of its methods.
		// Look up the method index in orig, and only instantiate method at the
		// matching index (if any).
		if i := n.Origin().methodIndex(name, foldCase); i >= 0 {
			// For instances, m.Method(i) will be different from the orig method.
			return i, n.Method(i)
		}
	}
	return -1, nil
}

// context returns the type-checker context.
func (check *Checker) context() *Context {
	if check.ctxt == nil {
		check.ctxt = NewContext()
	}
	return check.ctxt
}

// expandUnderlying substitutes type arguments in the underlying type n.orig,
// returning the result. Returns Typ[Invalid] if there was an error.
func (n *Named) expandUnderlying() Type {
	check := n.check
	if check != nil && check.conf.Trace {
		check.trace(n.obj.pos, "-- Named.expandUnderlying %s", n)
		check.indent++
		defer func() {
			check.indent--
			check.trace(n.obj.pos, "=> %s (tparams = %s, under = %s)", n, n.tparams.list(), n.underlying)
		}()
	}

	assert(n.inst.orig.underlying != nil)
	if n.inst.ctxt == nil {
		n.inst.ctxt = NewContext()
	}

	orig := n.inst.orig
	targs := n.inst.targs

	if asNamed(orig.underlying) != nil {
		// We should only get a Named underlying type here during type checking
		// (for example, in recursive type declarations).
		assert(check != nil)
	}

	if orig.tparams.Len() != targs.Len() {
		// Mismatching arg and tparam length may be checked elsewhere.
		return Typ[Invalid]
	}

	// Ensure that an instance is recorded before substituting, so that we
	// resolve n for any recursive references.
	h := n.inst.ctxt.instanceHash(orig, targs.list())
	n2 := n.inst.ctxt.update(h, orig, n.TypeArgs().list(), n)
	assert(n == n2)

	smap := makeSubstMap(orig.tparams.list(), targs.list())
	var ctxt *Context
	if check != nil {
		ctxt = check.context()
	}
	underlying := n.check.subst(n.obj.pos, orig.underlying, smap, n, ctxt)
	// If the underlying type of n is an interface, we need to set the receiver of
	// its methods accurately -- we set the receiver of interface methods on
	// the RHS of a type declaration to the defined type.
	if iface, _ := underlying.(*Interface); iface != nil {
		if methods, copied := replaceRecvType(iface.methods, orig, n); copied {
			// If the underlying type doesn't actually use type parameters, it's
			// possible that it wasn't substituted. In this case we need to create
			// a new *Interface before modifying receivers.
			if iface == orig.underlying {
				old := iface
				iface = check.newInterface()
				iface.embeddeds = old.embeddeds
				assert(old.complete) // otherwise we are copying incomplete data
				iface.complete = old.complete
				iface.implicit = old.implicit // should be false but be conservative
				underlying = iface
			}
			iface.methods = methods
			iface.tset = nil // recompute type set with new methods

			// If check != nil, check.newInterface will have saved the interface for later completion.
			if check == nil { // golang/go#61561: all newly created interfaces must be fully evaluated
				iface.typeSet()
			}
		}
	}

	return underlying
}

// safeUnderlying returns the underlying type of typ without expanding
// instances, to avoid infinite recursion.
//
// TODO(rfindley): eliminate this function or give it a better name.
func safeUnderlying(typ Type) Type {
	if t := asNamed(typ); t != nil {
		return t.underlying
	}
	return typ.Underlying()
}

"""



```