Response: Let's break down the thought process for analyzing the provided Go code snippet.

**1. Initial Scan and Identification of the Core Structure:**

The first thing I noticed was the `_TypeSet` struct. The name itself strongly suggests it represents a set of types. The comments in the initial section further confirm this, mentioning it represents the "type set of an interface." The fields `methods`, `terms`, and `comparable` hinted at the components of this type set.

**2. Analyzing the `_TypeSet` Fields:**

* **`methods []*Func`:**  This was relatively straightforward. A slice of `*Func` suggests this stores the methods associated with the type set. The comment "sorted by unique ID" was an important detail.
* **`terms termlist`:** This was less immediately obvious. The name "termlist" and the comment "type terms of the type set" suggested this holds information about the concrete types allowed in the set. The custom type `termlist` indicated it's a domain-specific way of representing these terms.
* **`comparable bool`:** This was clear. It signifies whether all types in the set must be comparable. The invariant comment provided crucial context: `!comparable || terms.isAll()`. This meant `comparable` is only true if the `terms` represent *all* types.

**3. Examining the API Methods:**

I started going through the methods defined on `*_TypeSet`:

* **`IsEmpty()` and `IsAll()`:** These were self-explanatory, checking for an empty or universal type set.
* **`IsMethodSet()`:** This was interesting. The comment "fully described by its method set" combined with the implementation `!s.comparable && s.terms.isAll()` implied that an interface defined purely by its methods (and allowing any type implementing those methods) has this property.
* **`IsComparable()`:** This method checked if all types in the set are comparable. The logic considered both the `terms` and the `comparable` flag. The recursive call to `comparableType` was a detail to note for later if a deeper dive was needed.
* **`NumMethods()` and `Method()`:** These were straightforward accessors for the methods.
* **`LookupMethod()`:**  This looked up a method by name and package.
* **`String()`:**  This was for representing the type set as a string, useful for debugging and potentially error messages. The different cases (empty, all, with methods/terms) indicated the complexity of representing a type set.

**4. Delving into the Implementation Methods:**

* **`hasTerms()`:**  A helper to quickly check if the type set has specific type terms.
* **`subsetOf()`:**  Checks if one type set is a subset of another, based on the `terms`.
* **`typeset()`:** This was a key method. The comment "iterator over the (type/underlying type) pairs" was crucial. The conditional handling based on `s.hasTerms()` and the logic for unaliasing and getting the underlying type were important details.
* **`is()`:** This method allowed applying a predicate function to the terms. The handling of the case where there are no specific terms was notable.
* **`topTypeSet`:**  This seemed to represent the type set of the empty interface (`interface{}`).
* **`computeInterfaceTypeSet()`:** This was a complex function. The comments about "not fully set up yet," "infinitely expanding interface," and the collection of methods and terms from embedded interfaces were significant. The logic around intersecting term lists (`intersectTermLists`) pointed to how the type set is built up from its components.
* **`intersectTermLists()`:**  This function clearly handled the intersection of term lists and the merging of the `comparable` flag. The filtering for comparable types when the `comparable` flag is set was important.
* **`compareFunc()` and `sortMethods()`/`assertSortedMethods()`:** These clearly dealt with the sorting of methods, as mentioned in the `_TypeSet` definition.
* **`invalidTypeSet`:** This represented an error state for type sets.
* **`computeUnionTypeSet()`:** This handled the creation of type sets for union types. The recursion and the `maxTermCount` check were notable.

**5. Inferring the Go Feature:**

Based on the analysis, especially the focus on interfaces, methods, and type constraints (including the handling of union types introduced in later Go versions), it became clear that this code implements the type set representation used for **interface type checking and implementation checks**. The handling of embedded interfaces and the intersection/union of type sets strongly pointed in this direction.

**6. Constructing the Go Code Example:**

To illustrate, I focused on the key aspects:

* **Basic interface with methods:**  Demonstrating the `methods` part of the type set.
* **Interface with type constraints (using `T`):** Showing the `terms` part.
* **Embedding interfaces:** Illustrating how methods and type constraints are combined.
* **Union types in interfaces:**  Highlighting the handling of `|`.

**7. Considering Potential User Errors:**

I thought about common pitfalls when working with interfaces:

* **Forgetting to implement all methods:** This is a classic Go interface error.
* **Misunderstanding type constraints:**  Especially with the introduction of generics and type sets. Trying to use types that don't match the constraints.
* **Overlapping embedded interfaces with conflicting methods (pre-Go 1.14):** This was explicitly mentioned in the code comments.

**8. Command-line Arguments:**

I reviewed the code for any direct interaction with command-line arguments. Since it's within the `cmd/compile` package, it's part of the compiler. Thus, the relevant arguments would be those passed to the `go build` or `go run` commands, specifically those that influence type checking (e.g., language version flags).

**Self-Correction/Refinement during the Process:**

* Initially, I might have focused too much on individual methods without seeing the bigger picture. Stepping back and looking at the overall purpose of `_TypeSet` helped.
* The `termlist` type required more investigation to understand its role fully. The methods defined on it (though not shown in the snippet) would provide further clues.
*  The distinction between the `methods` and `terms` was initially a bit subtle but became clearer when analyzing `computeInterfaceTypeSet` and `intersectTermLists`. The comments were very helpful here.
*  Recognizing the Go version dependencies (go1.14 and go1.18) was important for understanding certain code sections.

By following these steps, combining code analysis with understanding the surrounding context and relevant Go language features, I could arrive at a comprehensive explanation of the code snippet's functionality.
这段代码是 Go 语言编译器 `cmd/compile/internal/types2` 包中 `typeset.go` 文件的一部分。它定义了 `_TypeSet` 结构体以及与其相关的操作，用于表示和操作接口的类型集合（type set）。

**主要功能:**

1. **表示接口的类型集合 (Type Set Representation):** `_TypeSet` 结构体用于表示一个接口所允许实现的具体类型集合。这个集合由两部分组成：
    * `methods`: 接口显式声明的所有方法。
    * `terms`: 类型项（type terms），用于描述接口允许的具体类型。类型项可以是具体的类型，也可以是形如 `~T` 的近似类型（表示底层类型为 `T` 的所有类型）。
    * `comparable`: 一个布尔值，表示类型集合中的所有类型是否都是可比较的。

2. **类型集合的运算:** 代码提供了一些方法来操作类型集合，例如：
    * `IsEmpty()`: 判断类型集合是否为空。
    * `IsAll()`: 判断类型集合是否包含所有类型（对应于空接口 `interface{}`）。
    * `IsMethodSet()`: 判断接口是否完全由其方法集合描述（即没有类型约束）。
    * `IsComparable()`: 判断类型集合中的所有类型是否可比较。
    * `subsetOf()`: 判断一个类型集合是否是另一个类型集合的子集。
    * `intersectTermLists()`: 计算两个类型项列表的交集，并更新 `comparable` 标志。
    * `union()`: (在 `termlist` 结构体中，虽然代码片段中没有完全展示) 计算类型项列表的并集。

3. **方法查找:**  提供了 `NumMethods()`, `Method()`, 和 `LookupMethod()` 方法来访问和查找接口的方法。

4. **字符串表示:** `String()` 方法将类型集合格式化为字符串，方便调试和查看。

5. **计算接口的类型集合:** `computeInterfaceTypeSet()` 函数是核心功能之一，它负责根据接口的定义（包括内嵌接口和类型约束）计算出接口的 `_TypeSet`。

6. **计算联合类型的类型集合:** `computeUnionTypeSet()` 函数负责计算联合类型（union type，例如 `int | string`）的类型集合。

**推理出的 Go 语言功能实现: 接口的类型约束 (Type Constraints for Interfaces) 和联合类型 (Union Types)**

这段代码是 Go 语言中为了支持更强大的接口功能而引入的类型约束和联合类型的底层实现。在 Go 1.18 之前，接口只能通过定义方法来约束类型。Go 1.18 引入了类型参数和类型约束，允许在接口中直接声明允许的类型。联合类型也是在 Go 1.18 中引入的，可以作为接口类型约束的一部分。

**Go 代码举例说明:**

```go
package main

import "fmt"

// 没有类型约束的接口
type Stringer interface {
	String() string
}

// 带有类型约束的接口 (Go 1.18+)
type Number interface {
	int | int64 | float64
}

// 带有方法和类型约束的接口 (Go 1.18+)
type PrintableNumber interface {
	Number
	Print()
}

// 带有近似类型约束的接口 (Go 1.18+)
type MyInt interface {
	~int
}

func printString(s Stringer) {
	fmt.Println(s.String())
}

func printNumber(n Number) {
	fmt.Println(n)
}

func main() {
	var s Stringer = "hello"
	printString(s)

	var i Number = 10
	printNumber(i)

	var f Number = 3.14
	printNumber(f)

	// 类型约束确保了传入 Number 接口的值只能是 int, int64 或 float64

	var myInt MyInt = 100
	fmt.Println(myInt) // 可以将 int 类型的值赋值给 MyInt 接口

	type myCustomInt int
	var customInt myCustomInt = 200
	var myCustomIntVar MyInt = customInt // 可以将底层类型为 int 的自定义类型赋值给 MyInt

}
```

**假设的输入与输出 (针对 `computeInterfaceTypeSet`)**

假设我们有以下接口定义：

```go
package mypackage

type Reader interface {
	Read() string
}

type Writer interface {
	Write(s string)
}

type ReadWriter interface {
	Reader
	Writer
}

type IntOrString interface {
	int | string
}
```

**输入到 `computeInterfaceTypeSet` 的 `ityp` (对于 `ReadWriter` 接口):**

* `ityp.methods`: 包含 `Read()` 和 `Write(string)` 两个方法 (假设已经解析并创建了对应的 `*Func` 对象)。
* `ityp.embeddeds`: 包含 `mypackage.Reader` 和 `mypackage.Writer` 两个类型。

**可能的输出 `ityp.tset`:**

* `methods`: 包含 `Read()` 和 `Write(string)` 两个 `*Func` 对象，并且已经按照唯一 ID 排序。
* `terms`:  `terms.isAll()` 为 `true`，因为 `ReadWriter` 接口没有显式的类型约束。
* `comparable`: `false`，因为 `ReadWriter` 接口没有要求类型是可比较的。

**输入到 `computeInterfaceTypeSet` 的 `ityp` (对于 `IntOrString` 接口):**

* `ityp.methods`: 空。
* `ityp.embeddeds`: 包含 `int` 和 `string` 两个类型 (包装在相应的类型项中)。

**可能的输出 `ityp.tset`:**

* `methods`: 空。
* `terms`: 包含两个类型项，分别对应 `int` 和 `string`。
* `comparable`: `false`。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它属于编译器内部的类型检查逻辑。然而，编译器的命令行参数会影响到这段代码的执行。例如：

* **`-lang` 或 `-gcflags=-std=go1.18`:**  指定 Go 语言版本会影响编译器是否启用对类型约束和联合类型的支持。如果指定了较早的版本，编译器可能会忽略或报错与这些新特性相关的代码。
* **编译器优化相关的参数:**  虽然不直接影响类型集合的计算逻辑，但可能会影响编译器的整体执行流程。

**使用者易犯错的点 (基于推理):**

1. **未能实现接口的所有方法:**  这是使用接口最常见的错误。如果一个类型声称实现了某个接口，但缺少接口中定义的方法，编译器会报错。
   ```go
   type MyType struct {}

   // 缺少 String() 方法
   // func (m MyType) String() string {
   // 	return "my type"
   // }

   func main() {
       var s Stringer = MyType{} // 编译错误: MyType does not implement Stringer (missing method String)
       printString(s)
   }
   ```

2. **类型约束不匹配:**  对于带有类型约束的接口，尝试使用不符合约束的类型会导致编译错误。
   ```go
   func printNumber(n Number) { /* ... */ }

   func main() {
       var b bool = true
       // printNumber(b) // 编译错误: cannot use bool as type Number in argument to printNumber
   }
   ```

3. **对近似类型约束的理解不足:**  使用 `~T` 表示底层类型为 `T` 的所有类型。用户可能会错误地认为只有 `T` 本身才满足约束。
   ```go
   type MyInt int

   func takesMyInt(mi MyInt) {
       fmt.Println(mi)
   }

   func main() {
       var i int = 10
       // takesMyInt(i) // 编译错误: cannot use i (variable of type int) as MyInt value in argument to takesMyInt

       var myI MyInt = 20
       takesMyInt(myI) // OK
   }
   ```
   **修正:** 如果接口定义为 `interface{ ~int }`，那么 `int` 和所有底层类型为 `int` 的自定义类型都满足约束。

4. **在 Go 1.18 之前的版本中使用类型约束或联合类型:** 这会导致编译错误，因为这些是 Go 1.18 引入的新特性。

总而言之，这段代码是 Go 语言编译器中实现接口类型集合的关键部分，它为接口的类型约束和联合类型提供了底层的支持。理解这段代码有助于更深入地理解 Go 语言的类型系统和接口机制。

### 提示词
```
这是路径为go/src/cmd/compile/internal/types2/typeset.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	. "internal/types/errors"
	"slices"
	"strings"
)

// ----------------------------------------------------------------------------
// API

// A _TypeSet represents the type set of an interface.
// Because of existing language restrictions, methods can be "factored out"
// from the terms. The actual type set is the intersection of the type set
// implied by the methods and the type set described by the terms and the
// comparable bit. To test whether a type is included in a type set
// ("implements" relation), the type must implement all methods _and_ be
// an element of the type set described by the terms and the comparable bit.
// If the term list describes the set of all types and comparable is true,
// only comparable types are meant; in all other cases comparable is false.
type _TypeSet struct {
	methods    []*Func  // all methods of the interface; sorted by unique ID
	terms      termlist // type terms of the type set
	comparable bool     // invariant: !comparable || terms.isAll()
}

// IsEmpty reports whether s is the empty set.
func (s *_TypeSet) IsEmpty() bool { return s.terms.isEmpty() }

// IsAll reports whether s is the set of all types (corresponding to the empty interface).
func (s *_TypeSet) IsAll() bool { return s.IsMethodSet() && len(s.methods) == 0 }

// IsMethodSet reports whether the interface t is fully described by its method set.
func (s *_TypeSet) IsMethodSet() bool { return !s.comparable && s.terms.isAll() }

// IsComparable reports whether each type in the set is comparable.
func (s *_TypeSet) IsComparable(seen map[Type]bool) bool {
	if s.terms.isAll() {
		return s.comparable
	}
	return s.is(func(t *term) bool {
		return t != nil && comparableType(t.typ, false, seen, nil)
	})
}

// NumMethods returns the number of methods available.
func (s *_TypeSet) NumMethods() int { return len(s.methods) }

// Method returns the i'th method of s for 0 <= i < s.NumMethods().
// The methods are ordered by their unique ID.
func (s *_TypeSet) Method(i int) *Func { return s.methods[i] }

// LookupMethod returns the index of and method with matching package and name, or (-1, nil).
func (s *_TypeSet) LookupMethod(pkg *Package, name string, foldCase bool) (int, *Func) {
	return methodIndex(s.methods, pkg, name, foldCase)
}

func (s *_TypeSet) String() string {
	switch {
	case s.IsEmpty():
		return "∅"
	case s.IsAll():
		return "𝓤"
	}

	hasMethods := len(s.methods) > 0
	hasTerms := s.hasTerms()

	var buf strings.Builder
	buf.WriteByte('{')
	if s.comparable {
		buf.WriteString("comparable")
		if hasMethods || hasTerms {
			buf.WriteString("; ")
		}
	}
	for i, m := range s.methods {
		if i > 0 {
			buf.WriteString("; ")
		}
		buf.WriteString(m.String())
	}
	if hasMethods && hasTerms {
		buf.WriteString("; ")
	}
	if hasTerms {
		buf.WriteString(s.terms.String())
	}
	buf.WriteString("}")
	return buf.String()
}

// ----------------------------------------------------------------------------
// Implementation

// hasTerms reports whether s has specific type terms.
func (s *_TypeSet) hasTerms() bool { return !s.terms.isEmpty() && !s.terms.isAll() }

// subsetOf reports whether s1 ⊆ s2.
func (s1 *_TypeSet) subsetOf(s2 *_TypeSet) bool { return s1.terms.subsetOf(s2.terms) }

// typeset is an iterator over the (type/underlying type) pairs in s.
// If s has no specific terms, typeset calls yield with (nil, nil).
// In any case, typeset is guaranteed to call yield at least once.
func (s *_TypeSet) typeset(yield func(t, u Type) bool) {
	if !s.hasTerms() {
		yield(nil, nil)
		return
	}

	for _, t := range s.terms {
		assert(t.typ != nil)
		// Unalias(x) == under(x) for ~x terms
		u := Unalias(t.typ)
		if !t.tilde {
			u = under(u)
		}
		if debug {
			assert(Identical(u, under(u)))
		}
		if !yield(t.typ, u) {
			break
		}
	}
}

// is calls f with the specific type terms of s and reports whether
// all calls to f returned true. If there are no specific terms, is
// returns the result of f(nil).
func (s *_TypeSet) is(f func(*term) bool) bool {
	if !s.hasTerms() {
		return f(nil)
	}
	for _, t := range s.terms {
		assert(t.typ != nil)
		if !f(t) {
			return false
		}
	}
	return true
}

// topTypeSet may be used as type set for the empty interface.
var topTypeSet = _TypeSet{terms: allTermlist}

// computeInterfaceTypeSet may be called with check == nil.
func computeInterfaceTypeSet(check *Checker, pos syntax.Pos, ityp *Interface) *_TypeSet {
	if ityp.tset != nil {
		return ityp.tset
	}

	// If the interface is not fully set up yet, the type set will
	// not be complete, which may lead to errors when using the
	// type set (e.g. missing method). Don't compute a partial type
	// set (and don't store it!), so that we still compute the full
	// type set eventually. Instead, return the top type set and
	// let any follow-on errors play out.
	//
	// TODO(gri) Consider recording when this happens and reporting
	// it as an error (but only if there were no other errors so
	// to not have unnecessary follow-on errors).
	if !ityp.complete {
		return &topTypeSet
	}

	if check != nil && check.conf.Trace {
		// Types don't generally have position information.
		// If we don't have a valid pos provided, try to use
		// one close enough.
		if !pos.IsKnown() && len(ityp.methods) > 0 {
			pos = ityp.methods[0].pos
		}

		check.trace(pos, "-- type set for %s", ityp)
		check.indent++
		defer func() {
			check.indent--
			check.trace(pos, "=> %s ", ityp.typeSet())
		}()
	}

	// An infinitely expanding interface (due to a cycle) is detected
	// elsewhere (Checker.validType), so here we simply assume we only
	// have valid interfaces. Mark the interface as complete to avoid
	// infinite recursion if the validType check occurs later for some
	// reason.
	ityp.tset = &_TypeSet{terms: allTermlist} // TODO(gri) is this sufficient?

	var unionSets map[*Union]*_TypeSet
	if check != nil {
		if check.unionTypeSets == nil {
			check.unionTypeSets = make(map[*Union]*_TypeSet)
		}
		unionSets = check.unionTypeSets
	} else {
		unionSets = make(map[*Union]*_TypeSet)
	}

	// Methods of embedded interfaces are collected unchanged; i.e., the identity
	// of a method I.m's Func Object of an interface I is the same as that of
	// the method m in an interface that embeds interface I. On the other hand,
	// if a method is embedded via multiple overlapping embedded interfaces, we
	// don't provide a guarantee which "original m" got chosen for the embedding
	// interface. See also go.dev/issue/34421.
	//
	// If we don't care to provide this identity guarantee anymore, instead of
	// reusing the original method in embeddings, we can clone the method's Func
	// Object and give it the position of a corresponding embedded interface. Then
	// we can get rid of the mpos map below and simply use the cloned method's
	// position.

	var seen objset
	var allMethods []*Func
	mpos := make(map[*Func]syntax.Pos) // method specification or method embedding position, for good error messages
	addMethod := func(pos syntax.Pos, m *Func, explicit bool) {
		switch other := seen.insert(m); {
		case other == nil:
			allMethods = append(allMethods, m)
			mpos[m] = pos
		case explicit:
			if check != nil {
				err := check.newError(DuplicateDecl)
				err.addf(atPos(pos), "duplicate method %s", m.name)
				err.addf(atPos(mpos[other.(*Func)]), "other declaration of method %s", m.name)
				err.report()
			}
		default:
			// We have a duplicate method name in an embedded (not explicitly declared) method.
			// Check method signatures after all types are computed (go.dev/issue/33656).
			// If we're pre-go1.14 (overlapping embeddings are not permitted), report that
			// error here as well (even though we could do it eagerly) because it's the same
			// error message.
			if check != nil {
				check.later(func() {
					if pos.IsKnown() && !check.allowVersion(go1_14) || !Identical(m.typ, other.Type()) {
						err := check.newError(DuplicateDecl)
						err.addf(atPos(pos), "duplicate method %s", m.name)
						err.addf(atPos(mpos[other.(*Func)]), "other declaration of method %s", m.name)
						err.report()
					}
				}).describef(atPos(pos), "duplicate method check for %s", m.name)
			}
		}
	}

	for _, m := range ityp.methods {
		addMethod(m.pos, m, true)
	}

	// collect embedded elements
	allTerms := allTermlist
	allComparable := false
	for i, typ := range ityp.embeddeds {
		// The embedding position is nil for imported interfaces.
		// We don't need to do version checks in those cases.
		var pos syntax.Pos // embedding position
		if ityp.embedPos != nil {
			pos = (*ityp.embedPos)[i]
		}
		var comparable bool
		var terms termlist
		switch u := under(typ).(type) {
		case *Interface:
			// For now we don't permit type parameters as constraints.
			assert(!isTypeParam(typ))
			tset := computeInterfaceTypeSet(check, pos, u)
			// If typ is local, an error was already reported where typ is specified/defined.
			if pos.IsKnown() && check != nil && check.isImportedConstraint(typ) && !check.verifyVersionf(atPos(pos), go1_18, "embedding constraint interface %s", typ) {
				continue
			}
			comparable = tset.comparable
			for _, m := range tset.methods {
				addMethod(pos, m, false) // use embedding position pos rather than m.pos
			}
			terms = tset.terms
		case *Union:
			if pos.IsKnown() && check != nil && !check.verifyVersionf(atPos(pos), go1_18, "embedding interface element %s", u) {
				continue
			}
			tset := computeUnionTypeSet(check, unionSets, pos, u)
			if tset == &invalidTypeSet {
				continue // ignore invalid unions
			}
			assert(!tset.comparable)
			assert(len(tset.methods) == 0)
			terms = tset.terms
		default:
			if !isValid(u) {
				continue
			}
			if pos.IsKnown() && check != nil && !check.verifyVersionf(atPos(pos), go1_18, "embedding non-interface type %s", typ) {
				continue
			}
			terms = termlist{{false, typ}}
		}

		// The type set of an interface is the intersection of the type sets of all its elements.
		// Due to language restrictions, only embedded interfaces can add methods, they are handled
		// separately. Here we only need to intersect the term lists and comparable bits.
		allTerms, allComparable = intersectTermLists(allTerms, allComparable, terms, comparable)
	}

	ityp.tset.comparable = allComparable
	if len(allMethods) != 0 {
		sortMethods(allMethods)
		ityp.tset.methods = allMethods
	}
	ityp.tset.terms = allTerms

	return ityp.tset
}

// TODO(gri) The intersectTermLists function belongs to the termlist implementation.
//           The comparable type set may also be best represented as a term (using
//           a special type).

// intersectTermLists computes the intersection of two term lists and respective comparable bits.
// xcomp, ycomp are valid only if xterms.isAll() and yterms.isAll() respectively.
func intersectTermLists(xterms termlist, xcomp bool, yterms termlist, ycomp bool) (termlist, bool) {
	terms := xterms.intersect(yterms)
	// If one of xterms or yterms is marked as comparable,
	// the result must only include comparable types.
	comp := xcomp || ycomp
	if comp && !terms.isAll() {
		// only keep comparable terms
		i := 0
		for _, t := range terms {
			assert(t.typ != nil)
			if comparableType(t.typ, false /* strictly comparable */, nil, nil) {
				terms[i] = t
				i++
			}
		}
		terms = terms[:i]
		if !terms.isAll() {
			comp = false
		}
	}
	assert(!comp || terms.isAll()) // comparable invariant
	return terms, comp
}

func compareFunc(a, b *Func) int {
	return a.cmp(&b.object)
}

func sortMethods(list []*Func) {
	slices.SortFunc(list, compareFunc)
}

func assertSortedMethods(list []*Func) {
	if !debug {
		panic("assertSortedMethods called outside debug mode")
	}
	if !slices.IsSortedFunc(list, compareFunc) {
		panic("methods not sorted")
	}
}

// invalidTypeSet is a singleton type set to signal an invalid type set
// due to an error. It's also a valid empty type set, so consumers of
// type sets may choose to ignore it.
var invalidTypeSet _TypeSet

// computeUnionTypeSet may be called with check == nil.
// The result is &invalidTypeSet if the union overflows.
func computeUnionTypeSet(check *Checker, unionSets map[*Union]*_TypeSet, pos syntax.Pos, utyp *Union) *_TypeSet {
	if tset, _ := unionSets[utyp]; tset != nil {
		return tset
	}

	// avoid infinite recursion (see also computeInterfaceTypeSet)
	unionSets[utyp] = new(_TypeSet)

	var allTerms termlist
	for _, t := range utyp.terms {
		var terms termlist
		u := under(t.typ)
		if ui, _ := u.(*Interface); ui != nil {
			// For now we don't permit type parameters as constraints.
			assert(!isTypeParam(t.typ))
			terms = computeInterfaceTypeSet(check, pos, ui).terms
		} else if !isValid(u) {
			continue
		} else {
			if t.tilde && !Identical(t.typ, u) {
				// There is no underlying type which is t.typ.
				// The corresponding type set is empty.
				t = nil // ∅ term
			}
			terms = termlist{(*term)(t)}
		}
		// The type set of a union expression is the union
		// of the type sets of each term.
		allTerms = allTerms.union(terms)
		if len(allTerms) > maxTermCount {
			if check != nil {
				check.errorf(atPos(pos), InvalidUnion, "cannot handle more than %d union terms (implementation limitation)", maxTermCount)
			}
			unionSets[utyp] = &invalidTypeSet
			return unionSets[utyp]
		}
	}
	unionSets[utyp].terms = allTerms

	return unionSets[utyp]
}
```