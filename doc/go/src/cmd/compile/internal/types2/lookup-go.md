Response: The user wants to understand the functionality of the Go code snippet provided, specifically the `lookup.go` file in the `types2` package. I need to:

1. **List the functionalities** implemented in the code.
2. **Infer the high-level Go feature** this code contributes to and provide a Go code example.
3. If the code involves **reasoning about types**, illustrate with input and output examples.
4. If it handles **command-line arguments**, explain them.
5. Identify **common mistakes** users might make when interacting with this functionality.

Based on the function names and comments, the primary function appears to be related to looking up fields and methods within Go types. This is a core part of Go's type system and reflection capabilities.

Let's break down the functions:

- `LookupFieldOrMethod`:  Looks up a field or method.
- `lookupFieldOrMethod`: Internal version with case-folding option.
- `lookupFieldOrMethodImpl`: The core implementation of the lookup logic.
- `MissingMethod`: Checks if a type implements an interface.
- `missingMethod`: Internal version of `MissingMethod`.
- `hasAllMethods`: Checks if a type has all methods of an interface.
- `assertableTo`: Checks if a type can be asserted to another type.
- `newAssertableTo`: Newer version of `assertableTo` with additional interface handling.
- Helper functions like `deref`, `derefStructPtr`, `concat`, `fieldIndex`, `methodIndex`, and `consolidateMultiples` support the core lookup logic.

**Functionality List:**

1. **Field and Method Lookup:**  Finds a field or method by name within a given type, considering embedded fields and pointer indirections.
2. **Interface Implementation Check:** Determines if a given type implements a specified interface. This includes checking method signatures and receiver types.
3. **Type Assertion Check:** Verifies if a value of one type can be asserted to another type, particularly in the context of interfaces.
`go/src/cmd/compile/internal/types2/lookup.go` 文件主要负责在 Go 语言的类型系统中查找字段和方法。它实现了类型查找的核心逻辑，这是 Go 语言进行类型检查、方法调用和接口实现判断的关键部分。

**主要功能列举:**

1. **`LookupFieldOrMethod(T Type, addressable bool, pkg *Package, name string)`:**
   - 在类型 `T` 中查找指定包 `pkg` 的名称为 `name` 的字段或方法。
   - `addressable` 参数指示 `T` 是否是可寻址变量的类型（这对于方法查找很重要）。
   - 返回找到的对象 (`*Var` 或 `*Func`)，一个索引序列 (`[]int`) 指示查找路径（对于嵌入字段），以及一个布尔值 `indirect` 指示在查找路径上是否存在指针解引用。
   - 如果找不到匹配项，则返回 `nil` 对象。索引序列和 `indirect` 值会指示查找失败的原因（例如，歧义的名称或需要指针接收者但不可寻址）。

2. **`MissingMethod(V Type, T *Interface, static bool)`:**
   - 检查类型 `V` 是否实现了接口 `T`。
   - 对于非接口类型 `V`，如果 `T` 的所有方法都在 `V` 中存在，则认为实现了。
   - 对于接口类型 `V`，仅检查 `T` 中也在 `V` 中存在的方法是否具有匹配的类型（用于类型断言的场景）。
   - `static` 参数用于区分静态类型检查和运行时类型断言的检查。
   - 返回缺失的方法 (`*Func`) 以及一个布尔值 `wrongType` 指示缺失的方法是因为类型不匹配（例如，需要指针接收者或签名不一致）。

3. **辅助功能:**
   - **`lookupFieldOrMethodImpl`:** `LookupFieldOrMethod` 的实际实现，提供更底层的查找逻辑。
   - **`consolidateMultiples`:** 用于合并在嵌入字段查找过程中遇到的相同类型，避免重复搜索。
   - **`deref` 和 `derefStructPtr`:** 用于解引用指针类型，方便进行字段和方法查找。
   - **`concat`:** 用于拼接索引序列。
   - **`fieldIndex` 和 `methodIndex`:**  在给定的字段或方法列表中查找匹配的索引。
   - **`assertableTo` 和 `newAssertableTo`:** 检查一个类型的值是否可以断言为另一个类型。

**推理性功能实现 (接口实现检查):**

该文件中的 `MissingMethod` 函数实现了 Go 语言中接口实现的检查机制。当一个类型声称实现了某个接口，或者在类型断言时，Go 编译器和运行时需要验证该类型是否真正满足接口的要求，即包含了接口中定义的所有方法，并且方法签名必须匹配。

**Go 代码示例 (接口实现检查):**

```go
package main

import "fmt"

type Stringer interface {
	String() string
}

type MyInt int

func (i MyInt) String() string {
	return fmt.Sprintf("MyInt: %d", i)
}

type MyFloat float64

func main() {
	var s Stringer
	var i MyInt = 10
	var f MyFloat = 3.14

	// MyInt 实现了 Stringer 接口
	s = i
	fmt.Println(s.String()) // 输出: MyInt: 10

	// MyFloat 没有实现 Stringer 接口 (缺少 String() string 方法)
	// 下面的代码在编译时会报错:
	// cannot use f (variable of type MyFloat) as Stringer value in assignment:
	// MyFloat does not implement Stringer (missing method String)
	// s = f
}
```

**代码推理 (字段查找):**

假设有以下 Go 代码：

```go
package main

type Inner struct {
	Value int
}

type Outer struct {
	Inner
	Name string
}

func main() {
	o := Outer{Inner: Inner{Value: 42}, Name: "example"}
	// 假设调用 LookupFieldOrMethod(TypeOf(o), false, nil, "Value")
}
```

**假设输入:**

- `T`: `*types2.Named`，代表 `Outer` 类型。
- `addressable`: `false` (因为我们直接操作的是变量的值，而不是变量的地址).
- `pkg`: `nil` (假设查找的是当前包的成员).
- `name`: `"Value"`.

**推理过程:**

1. `LookupFieldOrMethod` 会调用 `lookupFieldOrMethodImpl`。
2. `lookupFieldOrMethodImpl` 首先检查 `Outer` 类型是否有直接名为 "Value" 的字段或方法。
3. 发现 `Outer` 中没有直接名为 "Value" 的字段或方法。
4. 接着，它会检查 `Outer` 的嵌入字段 `Inner`。
5. 在 `Inner` 类型中找到了名为 "Value" 的字段。
6. 返回结果：
   - `obj`: `*types2.Var`，代表 `Inner.Value` 字段。
   - `index`: `[]int{0, 0}`。第一个 `0` 代表 `Outer` 的第一个字段（即嵌入的 `Inner`），第二个 `0` 代表 `Inner` 的第一个字段 `Value`。
   - `indirect`: `false`，因为访问 `Value` 不需要指针解引用。

**假设输入 (查找方法):**

```go
package main

type MyType struct{}

func (m MyType) MyMethod() {}

func main() {
	var t MyType
	// 假设调用 LookupFieldOrMethod(TypeOf(t), true, nil, "MyMethod")
}
```

**假设输入:**

- `T`: `*types2.Named`，代表 `MyType` 类型。
- `addressable`: `true` (因为方法调用通常需要考虑接收者是否可寻址).
- `pkg`: `nil`.
- `name`: `"MyMethod"`.

**推理过程:**

1. `LookupFieldOrMethod` 调用 `lookupFieldOrMethodImpl`。
2. `lookupFieldOrMethodImpl` 检查 `MyType` 是否有名为 "MyMethod" 的方法。
3. 找到了 `MyMethod` 方法。
4. 返回结果：
   - `obj`: `*types2.Func`，代表 `MyType.MyMethod` 方法。
   - `index`: `[]int{0}`。`MyMethod` 是 `MyType` 直接声明的方法，索引为 0。
   - `indirect`: `false`。

**命令行参数处理:**

该代码片段本身不直接处理命令行参数。它的功能是类型系统内部的查找和检查，主要由 Go 编译器 (`go build`, `go run` 等) 在编译和类型检查阶段使用。命令行参数的处理发生在编译器的更高层。

**使用者易犯错的点:**

在实际使用中，开发者不会直接调用 `LookupFieldOrMethod` 或 `MissingMethod` 这些 `types2` 包的内部函数。然而，理解这些函数背后的逻辑有助于避免一些常见的错误，例如：

1. **接口实现不完整:**  如果一个类型声称实现了某个接口，但缺少接口中定义的方法或方法签名不匹配，编译器会报错。理解 `MissingMethod` 的检查逻辑可以帮助开发者更好地理解这些错误信息。

   **示例:**

   ```go
   type Reader interface {
       Read(p []byte) (n int, err error)
   }

   type MyReader struct {}

   func (r MyReader) Read(p []byte) int { // 错误: 返回值类型不匹配
       return 0
   }

   func main() {
       var r Reader = MyReader{} // 编译时会报错
   }
   ```

2. **方法接收者类型错误:**  当调用一个方法时，如果接收者类型不匹配（例如，尝试在值类型上调用指针接收者的方法，且该值不可寻址），编译器也会报错。`LookupFieldOrMethod` 中对 `addressable` 和 `indirect` 的处理与此相关。

   **示例:**

   ```go
   type Counter struct {
       count int
   }

   func (c *Counter) Increment() {
       c.count++
   }

   func main() {
       c := Counter{}
       // c.Increment() // 错误: cannot call pointer method on Counter literal
       (&c).Increment() // 正确
   }
   ```

总而言之，`go/src/cmd/compile/internal/types2/lookup.go` 是 Go 语言类型系统中的一个核心组件，它负责执行关键的类型查找和接口实现检查操作，为 Go 语言的静态类型安全和面向接口编程提供了基础。虽然开发者通常不会直接使用这个文件中的函数，但理解其功能有助于更好地理解 Go 语言的类型系统和避免相关的编程错误。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/types2/lookup.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file implements various field and method lookup functions.

package types2

import "bytes"

// Internal use of LookupFieldOrMethod: If the obj result is a method
// associated with a concrete (non-interface) type, the method's signature
// may not be fully set up. Call Checker.objDecl(obj, nil) before accessing
// the method's type.

// LookupFieldOrMethod looks up a field or method with given package and name
// in T and returns the corresponding *Var or *Func, an index sequence, and a
// bool indicating if there were any pointer indirections on the path to the
// field or method. If addressable is set, T is the type of an addressable
// variable (only matters for method lookups). T must not be nil.
//
// The last index entry is the field or method index in the (possibly embedded)
// type where the entry was found, either:
//
//  1. the list of declared methods of a named type; or
//  2. the list of all methods (method set) of an interface type; or
//  3. the list of fields of a struct type.
//
// The earlier index entries are the indices of the embedded struct fields
// traversed to get to the found entry, starting at depth 0.
//
// If no entry is found, a nil object is returned. In this case, the returned
// index and indirect values have the following meaning:
//
//   - If index != nil, the index sequence points to an ambiguous entry
//     (the same name appeared more than once at the same embedding level).
//
//   - If indirect is set, a method with a pointer receiver type was found
//     but there was no pointer on the path from the actual receiver type to
//     the method's formal receiver base type, nor was the receiver addressable.
func LookupFieldOrMethod(T Type, addressable bool, pkg *Package, name string) (obj Object, index []int, indirect bool) {
	if T == nil {
		panic("LookupFieldOrMethod on nil type")
	}
	return lookupFieldOrMethod(T, addressable, pkg, name, false)
}

// lookupFieldOrMethod is like LookupFieldOrMethod but with the additional foldCase parameter
// (see Object.sameId for the meaning of foldCase).
func lookupFieldOrMethod(T Type, addressable bool, pkg *Package, name string, foldCase bool) (obj Object, index []int, indirect bool) {
	// Methods cannot be associated to a named pointer type.
	// (spec: "The type denoted by T is called the receiver base type;
	// it must not be a pointer or interface type and it must be declared
	// in the same package as the method.").
	// Thus, if we have a named pointer type, proceed with the underlying
	// pointer type but discard the result if it is a method since we would
	// not have found it for T (see also go.dev/issue/8590).
	if t := asNamed(T); t != nil {
		if p, _ := t.Underlying().(*Pointer); p != nil {
			obj, index, indirect = lookupFieldOrMethodImpl(p, false, pkg, name, foldCase)
			if _, ok := obj.(*Func); ok {
				return nil, nil, false
			}
			return
		}
	}

	obj, index, indirect = lookupFieldOrMethodImpl(T, addressable, pkg, name, foldCase)

	// If we didn't find anything and if we have a type parameter with a core type,
	// see if there is a matching field (but not a method, those need to be declared
	// explicitly in the constraint). If the constraint is a named pointer type (see
	// above), we are ok here because only fields are accepted as results.
	const enableTParamFieldLookup = false // see go.dev/issue/51576
	if enableTParamFieldLookup && obj == nil && isTypeParam(T) {
		if t := coreType(T); t != nil {
			obj, index, indirect = lookupFieldOrMethodImpl(t, addressable, pkg, name, foldCase)
			if _, ok := obj.(*Var); !ok {
				obj, index, indirect = nil, nil, false // accept fields (variables) only
			}
		}
	}
	return
}

// lookupFieldOrMethodImpl is the implementation of lookupFieldOrMethod.
// Notably, in contrast to lookupFieldOrMethod, it won't find struct fields
// in base types of defined (*Named) pointer types T. For instance, given
// the declaration:
//
//	type T *struct{f int}
//
// lookupFieldOrMethodImpl won't find the field f in the defined (*Named) type T
// (methods on T are not permitted in the first place).
//
// Thus, lookupFieldOrMethodImpl should only be called by lookupFieldOrMethod
// and missingMethod (the latter doesn't care about struct fields).
//
// The resulting object may not be fully type-checked.
func lookupFieldOrMethodImpl(T Type, addressable bool, pkg *Package, name string, foldCase bool) (obj Object, index []int, indirect bool) {
	// WARNING: The code in this function is extremely subtle - do not modify casually!

	if name == "_" {
		return // blank fields/methods are never found
	}

	// Importantly, we must not call under before the call to deref below (nor
	// does deref call under), as doing so could incorrectly result in finding
	// methods of the pointer base type when T is a (*Named) pointer type.
	typ, isPtr := deref(T)

	// *typ where typ is an interface (incl. a type parameter) has no methods.
	if isPtr {
		if _, ok := under(typ).(*Interface); ok {
			return
		}
	}

	// Start with typ as single entry at shallowest depth.
	current := []embeddedType{{typ, nil, isPtr, false}}

	// seen tracks named types that we have seen already, allocated lazily.
	// Used to avoid endless searches in case of recursive types.
	//
	// We must use a lookup on identity rather than a simple map[*Named]bool as
	// instantiated types may be identical but not equal.
	var seen instanceLookup

	// search current depth
	for len(current) > 0 {
		var next []embeddedType // embedded types found at current depth

		// look for (pkg, name) in all types at current depth
		for _, e := range current {
			typ := e.typ

			// If we have a named type, we may have associated methods.
			// Look for those first.
			if named := asNamed(typ); named != nil {
				if alt := seen.lookup(named); alt != nil {
					// We have seen this type before, at a more shallow depth
					// (note that multiples of this type at the current depth
					// were consolidated before). The type at that depth shadows
					// this same type at the current depth, so we can ignore
					// this one.
					continue
				}
				seen.add(named)

				// look for a matching attached method
				if i, m := named.lookupMethod(pkg, name, foldCase); m != nil {
					// potential match
					// caution: method may not have a proper signature yet
					index = concat(e.index, i)
					if obj != nil || e.multiples {
						return nil, index, false // collision
					}
					obj = m
					indirect = e.indirect
					continue // we can't have a matching field or interface method
				}
			}

			switch t := under(typ).(type) {
			case *Struct:
				// look for a matching field and collect embedded types
				for i, f := range t.fields {
					if f.sameId(pkg, name, foldCase) {
						assert(f.typ != nil)
						index = concat(e.index, i)
						if obj != nil || e.multiples {
							return nil, index, false // collision
						}
						obj = f
						indirect = e.indirect
						continue // we can't have a matching interface method
					}
					// Collect embedded struct fields for searching the next
					// lower depth, but only if we have not seen a match yet
					// (if we have a match it is either the desired field or
					// we have a name collision on the same depth; in either
					// case we don't need to look further).
					// Embedded fields are always of the form T or *T where
					// T is a type name. If e.typ appeared multiple times at
					// this depth, f.typ appears multiple times at the next
					// depth.
					if obj == nil && f.embedded {
						typ, isPtr := deref(f.typ)
						// TODO(gri) optimization: ignore types that can't
						// have fields or methods (only Named, Struct, and
						// Interface types need to be considered).
						next = append(next, embeddedType{typ, concat(e.index, i), e.indirect || isPtr, e.multiples})
					}
				}

			case *Interface:
				// look for a matching method (interface may be a type parameter)
				if i, m := t.typeSet().LookupMethod(pkg, name, foldCase); m != nil {
					assert(m.typ != nil)
					index = concat(e.index, i)
					if obj != nil || e.multiples {
						return nil, index, false // collision
					}
					obj = m
					indirect = e.indirect
				}
			}
		}

		if obj != nil {
			// found a potential match
			// spec: "A method call x.m() is valid if the method set of (the type of) x
			//        contains m and the argument list can be assigned to the parameter
			//        list of m. If x is addressable and &x's method set contains m, x.m()
			//        is shorthand for (&x).m()".
			if f, _ := obj.(*Func); f != nil {
				// determine if method has a pointer receiver
				if f.hasPtrRecv() && !indirect && !addressable {
					return nil, nil, true // pointer/addressable receiver required
				}
			}
			return
		}

		current = consolidateMultiples(next)
	}

	return nil, nil, false // not found
}

// embeddedType represents an embedded type
type embeddedType struct {
	typ       Type
	index     []int // embedded field indices, starting with index at depth 0
	indirect  bool  // if set, there was a pointer indirection on the path to this field
	multiples bool  // if set, typ appears multiple times at this depth
}

// consolidateMultiples collects multiple list entries with the same type
// into a single entry marked as containing multiples. The result is the
// consolidated list.
func consolidateMultiples(list []embeddedType) []embeddedType {
	if len(list) <= 1 {
		return list // at most one entry - nothing to do
	}

	n := 0                     // number of entries w/ unique type
	prev := make(map[Type]int) // index at which type was previously seen
	for _, e := range list {
		if i, found := lookupType(prev, e.typ); found {
			list[i].multiples = true
			// ignore this entry
		} else {
			prev[e.typ] = n
			list[n] = e
			n++
		}
	}
	return list[:n]
}

func lookupType(m map[Type]int, typ Type) (int, bool) {
	// fast path: maybe the types are equal
	if i, found := m[typ]; found {
		return i, true
	}

	for t, i := range m {
		if Identical(t, typ) {
			return i, true
		}
	}

	return 0, false
}

type instanceLookup struct {
	// buf is used to avoid allocating the map m in the common case of a small
	// number of instances.
	buf [3]*Named
	m   map[*Named][]*Named
}

func (l *instanceLookup) lookup(inst *Named) *Named {
	for _, t := range l.buf {
		if t != nil && Identical(inst, t) {
			return t
		}
	}
	for _, t := range l.m[inst.Origin()] {
		if Identical(inst, t) {
			return t
		}
	}
	return nil
}

func (l *instanceLookup) add(inst *Named) {
	for i, t := range l.buf {
		if t == nil {
			l.buf[i] = inst
			return
		}
	}
	if l.m == nil {
		l.m = make(map[*Named][]*Named)
	}
	insts := l.m[inst.Origin()]
	l.m[inst.Origin()] = append(insts, inst)
}

// MissingMethod returns (nil, false) if V implements T, otherwise it
// returns a missing method required by T and whether it is missing or
// just has the wrong type: either a pointer receiver or wrong signature.
//
// For non-interface types V, or if static is set, V implements T if all
// methods of T are present in V. Otherwise (V is an interface and static
// is not set), MissingMethod only checks that methods of T which are also
// present in V have matching types (e.g., for a type assertion x.(T) where
// x is of interface type V).
func MissingMethod(V Type, T *Interface, static bool) (method *Func, wrongType bool) {
	return (*Checker)(nil).missingMethod(V, T, static, Identical, nil)
}

// missingMethod is like MissingMethod but accepts a *Checker as receiver,
// a comparator equivalent for type comparison, and a *string for error causes.
// The receiver may be nil if missingMethod is invoked through an exported
// API call (such as MissingMethod), i.e., when all methods have been type-
// checked.
// The underlying type of T must be an interface; T (rather than its under-
// lying type) is used for better error messages (reported through *cause).
// The comparator is used to compare signatures.
// If a method is missing and cause is not nil, *cause describes the error.
func (check *Checker) missingMethod(V, T Type, static bool, equivalent func(x, y Type) bool, cause *string) (method *Func, wrongType bool) {
	methods := under(T).(*Interface).typeSet().methods // T must be an interface
	if len(methods) == 0 {
		return nil, false
	}

	const (
		ok = iota
		notFound
		wrongName
		unexported
		wrongSig
		ambigSel
		ptrRecv
		field
	)

	state := ok
	var m *Func // method on T we're trying to implement
	var f *Func // method on V, if found (state is one of ok, wrongName, wrongSig)

	if u, _ := under(V).(*Interface); u != nil {
		tset := u.typeSet()
		for _, m = range methods {
			_, f = tset.LookupMethod(m.pkg, m.name, false)

			if f == nil {
				if !static {
					continue
				}
				state = notFound
				break
			}

			if !equivalent(f.typ, m.typ) {
				state = wrongSig
				break
			}
		}
	} else {
		for _, m = range methods {
			obj, index, indirect := lookupFieldOrMethodImpl(V, false, m.pkg, m.name, false)

			// check if m is ambiguous, on *V, or on V with case-folding
			if obj == nil {
				switch {
				case index != nil:
					state = ambigSel
				case indirect:
					state = ptrRecv
				default:
					state = notFound
					obj, _, _ = lookupFieldOrMethodImpl(V, false, m.pkg, m.name, true /* fold case */)
					f, _ = obj.(*Func)
					if f != nil {
						state = wrongName
						if f.name == m.name {
							// If the names are equal, f must be unexported
							// (otherwise the package wouldn't matter).
							state = unexported
						}
					}
				}
				break
			}

			// we must have a method (not a struct field)
			f, _ = obj.(*Func)
			if f == nil {
				state = field
				break
			}

			// methods may not have a fully set up signature yet
			if check != nil {
				check.objDecl(f, nil)
			}

			if !equivalent(f.typ, m.typ) {
				state = wrongSig
				break
			}
		}
	}

	if state == ok {
		return nil, false
	}

	if cause != nil {
		if f != nil {
			// This method may be formatted in funcString below, so must have a fully
			// set up signature.
			if check != nil {
				check.objDecl(f, nil)
			}
		}
		switch state {
		case notFound:
			switch {
			case isInterfacePtr(V):
				*cause = "(" + check.interfacePtrError(V) + ")"
			case isInterfacePtr(T):
				*cause = "(" + check.interfacePtrError(T) + ")"
			default:
				*cause = check.sprintf("(missing method %s)", m.Name())
			}
		case wrongName:
			fs, ms := check.funcString(f, false), check.funcString(m, false)
			*cause = check.sprintf("(missing method %s)\n\t\thave %s\n\t\twant %s", m.Name(), fs, ms)
		case unexported:
			*cause = check.sprintf("(unexported method %s)", m.Name())
		case wrongSig:
			fs, ms := check.funcString(f, false), check.funcString(m, false)
			if fs == ms {
				// Don't report "want Foo, have Foo".
				// Add package information to disambiguate (go.dev/issue/54258).
				fs, ms = check.funcString(f, true), check.funcString(m, true)
			}
			if fs == ms {
				// We still have "want Foo, have Foo".
				// This is most likely due to different type parameters with
				// the same name appearing in the instantiated signatures
				// (go.dev/issue/61685).
				// Rather than reporting this misleading error cause, for now
				// just point out that the method signature is incorrect.
				// TODO(gri) should find a good way to report the root cause
				*cause = check.sprintf("(wrong type for method %s)", m.Name())
				break
			}
			*cause = check.sprintf("(wrong type for method %s)\n\t\thave %s\n\t\twant %s", m.Name(), fs, ms)
		case ambigSel:
			*cause = check.sprintf("(ambiguous selector %s.%s)", V, m.Name())
		case ptrRecv:
			*cause = check.sprintf("(method %s has pointer receiver)", m.Name())
		case field:
			*cause = check.sprintf("(%s.%s is a field, not a method)", V, m.Name())
		default:
			panic("unreachable")
		}
	}

	return m, state == wrongSig || state == ptrRecv
}

// hasAllMethods is similar to checkMissingMethod but instead reports whether all methods are present.
// If V is not a valid type, or if it is a struct containing embedded fields with invalid types, the
// result is true because it is not possible to say with certainty whether a method is missing or not
// (an embedded field may have the method in question).
// If the result is false and cause is not nil, *cause describes the error.
// Use hasAllMethods to avoid follow-on errors due to incorrect types.
func (check *Checker) hasAllMethods(V, T Type, static bool, equivalent func(x, y Type) bool, cause *string) bool {
	if !isValid(V) {
		return true // we don't know anything about V, assume it implements T
	}
	m, _ := check.missingMethod(V, T, static, equivalent, cause)
	return m == nil || hasInvalidEmbeddedFields(V, nil)
}

// hasInvalidEmbeddedFields reports whether T is a struct (or a pointer to a struct) that contains
// (directly or indirectly) embedded fields with invalid types.
func hasInvalidEmbeddedFields(T Type, seen map[*Struct]bool) bool {
	if S, _ := under(derefStructPtr(T)).(*Struct); S != nil && !seen[S] {
		if seen == nil {
			seen = make(map[*Struct]bool)
		}
		seen[S] = true
		for _, f := range S.fields {
			if f.embedded && (!isValid(f.typ) || hasInvalidEmbeddedFields(f.typ, seen)) {
				return true
			}
		}
	}
	return false
}

func isInterfacePtr(T Type) bool {
	p, _ := under(T).(*Pointer)
	return p != nil && IsInterface(p.base)
}

// check may be nil.
func (check *Checker) interfacePtrError(T Type) string {
	assert(isInterfacePtr(T))
	if p, _ := under(T).(*Pointer); isTypeParam(p.base) {
		return check.sprintf("type %s is pointer to type parameter, not type parameter", T)
	}
	return check.sprintf("type %s is pointer to interface, not interface", T)
}

// funcString returns a string of the form name + signature for f.
// check may be nil.
func (check *Checker) funcString(f *Func, pkgInfo bool) string {
	buf := bytes.NewBufferString(f.name)
	var qf Qualifier
	if check != nil && !pkgInfo {
		qf = check.qualifier
	}
	w := newTypeWriter(buf, qf)
	w.pkgInfo = pkgInfo
	w.paramNames = false
	w.signature(f.typ.(*Signature))
	return buf.String()
}

// assertableTo reports whether a value of type V can be asserted to have type T.
// The receiver may be nil if assertableTo is invoked through an exported API call
// (such as AssertableTo), i.e., when all methods have been type-checked.
// The underlying type of V must be an interface.
// If the result is false and cause is not nil, *cause describes the error.
// TODO(gri) replace calls to this function with calls to newAssertableTo.
func (check *Checker) assertableTo(V, T Type, cause *string) bool {
	// no static check is required if T is an interface
	// spec: "If T is an interface type, x.(T) asserts that the
	//        dynamic type of x implements the interface T."
	if IsInterface(T) {
		return true
	}
	// TODO(gri) fix this for generalized interfaces
	return check.hasAllMethods(T, V, false, Identical, cause)
}

// newAssertableTo reports whether a value of type V can be asserted to have type T.
// It also implements behavior for interfaces that currently are only permitted
// in constraint position (we have not yet defined that behavior in the spec).
// The underlying type of V must be an interface.
// If the result is false and cause is not nil, *cause is set to the error cause.
func (check *Checker) newAssertableTo(V, T Type, cause *string) bool {
	// no static check is required if T is an interface
	// spec: "If T is an interface type, x.(T) asserts that the
	//        dynamic type of x implements the interface T."
	if IsInterface(T) {
		return true
	}
	return check.implements(T, V, false, cause)
}

// deref dereferences typ if it is a *Pointer (but not a *Named type
// with an underlying pointer type!) and returns its base and true.
// Otherwise it returns (typ, false).
func deref(typ Type) (Type, bool) {
	if p, _ := Unalias(typ).(*Pointer); p != nil {
		// p.base should never be nil, but be conservative
		if p.base == nil {
			if debug {
				panic("pointer with nil base type (possibly due to an invalid cyclic declaration)")
			}
			return Typ[Invalid], true
		}
		return p.base, true
	}
	return typ, false
}

// derefStructPtr dereferences typ if it is a (named or unnamed) pointer to a
// (named or unnamed) struct and returns its base. Otherwise it returns typ.
func derefStructPtr(typ Type) Type {
	if p, _ := under(typ).(*Pointer); p != nil {
		if _, ok := under(p.base).(*Struct); ok {
			return p.base
		}
	}
	return typ
}

// concat returns the result of concatenating list and i.
// The result does not share its underlying array with list.
func concat(list []int, i int) []int {
	var t []int
	t = append(t, list...)
	return append(t, i)
}

// fieldIndex returns the index for the field with matching package and name, or a value < 0.
// See Object.sameId for the meaning of foldCase.
func fieldIndex(fields []*Var, pkg *Package, name string, foldCase bool) int {
	if name != "_" {
		for i, f := range fields {
			if f.sameId(pkg, name, foldCase) {
				return i
			}
		}
	}
	return -1
}

// methodIndex returns the index of and method with matching package and name, or (-1, nil).
// See Object.sameId for the meaning of foldCase.
func methodIndex(methods []*Func, pkg *Package, name string, foldCase bool) (int, *Func) {
	if name != "_" {
		for i, m := range methods {
			if m.sameId(pkg, name, foldCase) {
				return i, m
			}
		}
	}
	return -1, nil
}

"""



```