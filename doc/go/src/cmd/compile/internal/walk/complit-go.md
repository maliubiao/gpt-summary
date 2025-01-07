Response: Let's break down the thought process to analyze the provided Go code snippet.

**1. Initial Understanding of the Request:**

The request asks for the functionality of a specific Go file (`complit.go`) within the Go compiler, particularly focusing on composite literals. It also requests examples, potential pitfalls, and handling of command-line arguments.

**2. High-Level Overview of the Code:**

Scanning the code reveals several key functions: `walkCompLit`, `fixedlit`, `slicelit`, `maplit`, `anylit`, and `oaslit`. The names themselves are quite suggestive: "walk composite literal," "fixed literal," "slice literal," "map literal," "any literal," and "oaslit" (likely "optimize assignment literal"). There are also helper functions like `isStaticCompositeLiteral`, `getdyn`, and `readonlystaticname`.

**3. `walkCompLit` - The Entry Point:**

This function is clearly the starting point for handling composite literals during the "walk" phase of compilation. The conditional check `isStaticCompositeLiteral(n) && !ssa.CanSSA(n.Type())` suggests a distinction between static and potentially dynamic composite literals and how they're handled regarding SSA (Static Single Assignment) optimization.

* **Hypothesis:** Static composite literals that can't be directly represented in SSA are placed in read-only memory. This optimizes for cases where the literal's value is known at compile time.
* **Supporting Evidence:** The call to `readonlystaticname` and `fixedlit(inInitFunction, initKindStatic, ...)` strongly supports this hypothesis.

**4. Exploring `fixedlit`, `slicelit`, `maplit`:**

These functions handle specific types of composite literals: arrays/structs, slices, and maps, respectively.

* **`fixedlit`:**  Iterates through the elements of arrays and structs. The `splitnode` function adapts based on whether it's an array or a struct. It seems to handle both static and dynamic initialization of elements.
* **`slicelit`:**  More complex due to the dynamic nature of slices. It differentiates between initialization in an `init` function and other functions. It seems to often involve creating a backing array (sometimes static) and then creating a slice from it. The code comments hint at optimizations for small slices and handling of "..." (variadic) arguments.
* **`maplit`:**  Handles map creation and initialization. It has a specific optimization for large maps, creating static arrays of keys and values and then iterating to populate the map. For smaller maps, it directly assigns key-value pairs.

**5. `anylit` - A General Handler:**

This function appears to be a more general handler for various types of "literals," not just composite ones. It handles cases like names, method expressions, and pointer literals, delegating to the more specific `fixedlit`, `slicelit`, and `maplit` when appropriate.

**6. `oaslit` - Assignment Optimization:**

This function tries to optimize assignments where the right-hand side is a composite literal. The checks it performs (identical types, no address taken, no use of LHS in RHS) suggest it aims to replace a simple assignment with a more efficient initialization process.

**7. Static vs. Dynamic Initialization (`isStaticCompositeLiteral`, `getdyn`):**

The code clearly distinguishes between static and dynamic initialization.

* **`isStaticCompositeLiteral`:**  Determines if a composite literal's value is fully known at compile time (all elements are also static literals).
* **`getdyn`:**  Determines if a composite literal contains any dynamic elements that require runtime initialization.

**8. Command-Line Arguments:**

The code snippet itself doesn't directly process command-line arguments. However, it uses `base.Ctxt.IsFIPS()` and `base.Ctxt.Flag_shared`, which are likely influenced by compiler flags. This points to the compiler's broader context handling these arguments.

**9. Potential Pitfalls:**

Analyzing the code and its logic reveals some potential areas where users might make mistakes:

* **Unexpected side effects in literal elements:** The code handles discarding elements with no side effects, but if an element's initialization has unexpected side effects, the compiler's optimizations might lead to surprising behavior.
* **Understanding the difference between static and dynamic initialization:** The compiler makes choices about how to initialize based on whether literals are static. Developers might not fully grasp when their literals qualify as static.
* **Performance implications of large literals:** The optimizations for large slices and maps are interesting. Users might not be aware of these internal optimizations and how they impact performance.

**10. Constructing Examples:**

Based on the understanding gained, the next step is to create illustrative Go code examples for each type of composite literal, demonstrating both static and dynamic initialization. This involves considering the conditions under which the compiler would choose different initialization paths.

**11. Refining and Organizing the Output:**

Finally, the information needs to be structured clearly, addressing each part of the original request: functionality overview, Go code examples with inputs and outputs, explanation of command-line argument influence (even if not directly processed in the snippet), and common mistakes.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps `walkCompLit` directly handles all cases.
* **Correction:** Realized that it delegates to specialized functions like `fixedlit`, `slicelit`, etc., based on the literal's type.
* **Initial thought:** Command-line arguments are irrelevant.
* **Correction:**  Recognized the usage of `base.Ctxt`, indicating influence from compiler flags.
* **Initial thought:**  Focus solely on the code's direct actions.
* **Correction:** Included inference about the *intent* behind the code (optimizations, static vs. dynamic initialization).

This iterative process of exploring the code, forming hypotheses, finding supporting evidence, and refining understanding is crucial to accurately analyze and explain the functionality of the provided Go code snippet.
这段Go语言代码是Go编译器 `cmd/compile/internal/walk` 包中处理复合字面量（Composite Literals）的一部分。它的主要功能是将Go语言源代码中的复合字面量表达式转换为编译器内部的表示形式，并生成相应的初始化代码。

**功能列表:**

1. **识别并处理各种复合字面量:**  `walkCompLit` 函数是处理复合字面量的入口，它可以处理以下类型的复合字面量：
    * 数组字面量 (`OARRAYLIT`)
    * 切片字面量 (`OSLICELIT`)
    * 映射字面量 (`OMAPLIT`)
    * 结构体字面量 (`OSTRUCTLIT`)
    * 指针字面量 (实际上是取地址表达式 `OPTRLIT`)

2. **静态与动态初始化区分:** 代码区分了静态复合字面量和动态复合字面量。
    * **静态复合字面量:**  如果一个复合字面量的所有元素都可以在编译时确定，那么它被认为是静态的。静态复合字面量可以直接放在只读数据段中，提高效率。
    * **动态复合字面量:** 如果复合字面量的某些元素需要在运行时计算，那么它被认为是动态的。

3. **静态复合字面量的处理:** 对于静态复合字面量，代码会：
    * 创建一个指向只读静态数据的符号 (`readonlystaticname`)。
    * 使用 `fixedlit` 函数将字面量的数据填充到这个静态符号中。
    * 将该字面量表达式替换为对该静态符号的引用。

4. **动态复合字面量的处理:** 对于动态复合字面量，代码会：
    * 创建一个临时变量来存储复合字面量的值 (`typecheck.TempAt`)。
    * 使用 `anylit` 函数生成将字面量的值赋给临时变量的初始化代码。

5. **`fixedlit` 函数:**  负责处理结构体和数组字面量的初始化。它可以处理静态和动态的元素，并将它们赋值给目标变量的相应字段或元素。

6. **`slicelit` 函数:**  专门处理切片字面量的初始化，它比较复杂，因为切片涉及到底层数组的创建和管理。它会根据情况选择在栈上还是堆上分配内存，并处理静态和动态的元素。

7. **`maplit` 函数:**  处理映射字面量的初始化。它会调用 `make` 函数创建映射，并根据映射条目的数量选择不同的初始化策略，例如对于大量静态条目，会先创建静态数组，然后循环赋值。

8. **`anylit` 函数:**  一个通用的处理各种字面量的函数，它根据字面量的类型调用相应的处理函数（如 `fixedlit`, `slicelit`, `maplit`）。

9. **`oaslit` 函数:**  处理复合字面量的赋值语句优化。如果赋值语句的右侧是一个复合字面量，并且满足某些条件（例如，左侧变量没有被取地址），它可以直接调用 `anylit` 来初始化左侧变量，避免不必要的中间步骤。

10. **`genAsStatic` 函数:**  用于生成将表达式的值赋给静态变量的初始化代码。

**Go语言功能实现推断与代码示例:**

这段代码主要实现了Go语言中复合字面量（Composite Literals）的语法功能。复合字面量允许在代码中直接创建和初始化结构体、数组、切片和映射类型的值。

**示例1: 结构体字面量**

```go
package main

type Point struct {
	X int
	Y int
}

func main() {
	p := Point{X: 10, Y: 20} // 结构体字面量
	println(p.X, p.Y)
}
```

**假设输入 (抽象表示):**  Go 编译器在解析到 `p := Point{X: 10, Y: 20}` 这行代码时，会创建一个 `OSTRUCTLIT` 类型的节点，其 `List` 包含两个 `OSTRUCTKEY` 节点，分别对应 `X: 10` 和 `Y: 20`。

**代码推理:** `walkCompLit` 函数会被调用，因为它识别到 `OSTRUCTLIT`。由于 `10` 和 `20` 都是常量，编译器可能会将这个字面量视为静态的。`fixedlit` 函数会被调用，它会生成将 `10` 和 `20` 分别赋值给 `p.X` 和 `p.Y` 的代码。如果编译器判断可以优化，可能会将 `Point{X: 10, Y: 20}` 直接放在只读数据段，然后将 `p` 指向那里。

**示例2: 切片字面量**

```go
package main

func main() {
	s := []int{1, 2, 3} // 切片字面量
	println(s[0], s[1], s[2])
}
```

**假设输入 (抽象表示):** Go 编译器会创建一个 `OSLICELIT` 类型的节点，其 `List` 包含三个 `OLITERAL` 节点，分别对应 `1`, `2`, `3`。

**代码推理:** `walkCompLit` 函数识别到 `OSLICELIT`，会调用 `slicelit` 函数。`slicelit` 函数会：
1. 分配一个底层数组来存储 `1`, `2`, `3`。
2. 初始化这个数组的元素。
3. 创建一个切片头（包含指向数组的指针、长度和容量）并赋值给 `s`。
如果 `s` 是在函数内部定义的局部变量，且字面量的值都是常量，编译器可能会将 `[3]int{1, 2, 3}` 放在静态数据区，然后在运行时创建一个指向该静态数组的切片。

**示例3: 包含运行时计算的切片字面量**

```go
package main

import "fmt"

func getValue() int {
	return 100
}

func main() {
	x := 50
	s := []int{1, 2, x + 10, getValue()} // 包含运行时计算的切片字面量
	fmt.Println(s)
}
```

**假设输入 (抽象表示):** `OSLICELIT` 节点的 `List` 包含 `OLITERAL(1)`, `OLITERAL(2)`, 一个加法表达式节点, 和一个函数调用节点。

**代码推理:**  `walkCompLit` 调用 `slicelit`。由于切片字面量中包含需要在运行时计算的表达式 (`x + 10` 和 `getValue()`)，编译器无法将其完全视为静态的。`slicelit` 会创建临时变量，并生成代码来计算这些表达式的值，然后将它们赋值给底层数组的相应元素。

**命令行参数处理:**

这段代码本身没有直接处理命令行参数。命令行参数的处理发生在 Go 编译器的其他阶段，例如 `flag` 包的使用。然而，这段代码中的一些逻辑可能会受到编译器标志的影响。例如：

* **`base.Ctxt.IsFIPS()` 和 `base.Ctxt.Flag_shared`:** 这些是编译器上下文中的标志，可能由命令行参数设置。例如，`-shared` 标志会影响是否生成共享库。`IsFIPS()` 可能与编译器的安全模式相关。这些标志会影响静态初始化的决策，例如在 FIPS 模式下，某些类型的静态初始化可能会被禁用。

**使用者易犯错的点 (示例):**

在大多数情况下，Go 语言的复合字面量使用起来相当直观。然而，在一些高级场景下，可能会出现一些容易出错的情况，但这些错误更多是关于理解 Go 语言本身的行为，而不是直接与 `complit.go` 的实现细节相关。

例如，一个可能被误解的点是关于切片字面量的容量：

```go
package main

import "fmt"

func main() {
	s := []int{1, 2, 3}
	fmt.Println(len(s), cap(s)) // 输出: 3 3
}
```

用户可能会认为切片字面量的容量总是等于其长度，但这只是在直接使用字面量创建切片时的默认行为。通过 `make` 函数创建切片时，可以显式指定容量。这与 `complit.go` 的实现有关，因为它需要决定如何分配底层数组。

另一个潜在的混淆点是关于结构体字面量的字段初始化顺序。虽然在 Go 1.17 之前，未明确初始化的字段的顺序可能会导致一些问题，但现在 Go 保证了初始化顺序与字段声明顺序一致，这消除了大部分潜在的错误。

**总结:**

`complit.go` 中的代码是 Go 编译器处理复合字面量的核心部分。它负责将源代码中的复合字面量转换为内部表示，并生成相应的初始化代码，同时考虑了静态和动态初始化的优化。虽然用户通常不需要直接了解这部分代码的细节，但理解其背后的原理有助于更好地理解 Go 语言的编译过程和一些潜在的性能优化。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/walk/complit.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package walk

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/ssa"
	"cmd/compile/internal/staticdata"
	"cmd/compile/internal/staticinit"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
)

// walkCompLit walks a composite literal node:
// OARRAYLIT, OSLICELIT, OMAPLIT, OSTRUCTLIT (all CompLitExpr), or OPTRLIT (AddrExpr).
func walkCompLit(n ir.Node, init *ir.Nodes) ir.Node {
	if isStaticCompositeLiteral(n) && !ssa.CanSSA(n.Type()) {
		n := n.(*ir.CompLitExpr) // not OPTRLIT
		// n can be directly represented in the read-only data section.
		// Make direct reference to the static data. See issue 12841.
		vstat := readonlystaticname(n.Type())
		fixedlit(inInitFunction, initKindStatic, n, vstat, init)
		return typecheck.Expr(vstat)
	}
	var_ := typecheck.TempAt(base.Pos, ir.CurFunc, n.Type())
	anylit(n, var_, init)
	return var_
}

// initContext is the context in which static data is populated.
// It is either in an init function or in any other function.
// Static data populated in an init function will be written either
// zero times (as a readonly, static data symbol) or
// one time (during init function execution).
// Either way, there is no opportunity for races or further modification,
// so the data can be written to a (possibly readonly) data symbol.
// Static data populated in any other function needs to be local to
// that function to allow multiple instances of that function
// to execute concurrently without clobbering each others' data.
type initContext uint8

const (
	inInitFunction initContext = iota
	inNonInitFunction
)

func (c initContext) String() string {
	if c == inInitFunction {
		return "inInitFunction"
	}
	return "inNonInitFunction"
}

// readonlystaticname returns a name backed by a read-only static data symbol.
func readonlystaticname(t *types.Type) *ir.Name {
	n := staticinit.StaticName(t)
	n.MarkReadonly()
	n.Linksym().Set(obj.AttrContentAddressable, true)
	n.Linksym().Set(obj.AttrLocal, true)
	return n
}

func isSimpleName(nn ir.Node) bool {
	if nn.Op() != ir.ONAME || ir.IsBlank(nn) {
		return false
	}
	n := nn.(*ir.Name)
	return n.OnStack()
}

// initGenType is a bitmap indicating the types of generation that will occur for a static value.
type initGenType uint8

const (
	initDynamic initGenType = 1 << iota // contains some dynamic values, for which init code will be generated
	initConst                           // contains some constant values, which may be written into data symbols
)

// getdyn calculates the initGenType for n.
// If top is false, getdyn is recursing.
func getdyn(n ir.Node, top bool) initGenType {
	switch n.Op() {
	default:
		// Handle constants in linker, except that linker cannot do
		// the relocations necessary for string constants in FIPS packages.
		if ir.IsConstNode(n) && (!n.Type().IsString() || !base.Ctxt.IsFIPS()) {
			return initConst
		}
		return initDynamic

	case ir.OSLICELIT:
		n := n.(*ir.CompLitExpr)
		if !top {
			return initDynamic
		}
		if n.Len/4 > int64(len(n.List)) {
			// <25% of entries have explicit values.
			// Very rough estimation, it takes 4 bytes of instructions
			// to initialize 1 byte of result. So don't use a static
			// initializer if the dynamic initialization code would be
			// smaller than the static value.
			// See issue 23780.
			return initDynamic
		}

	case ir.OARRAYLIT, ir.OSTRUCTLIT:
	}
	lit := n.(*ir.CompLitExpr)

	var mode initGenType
	for _, n1 := range lit.List {
		switch n1.Op() {
		case ir.OKEY:
			n1 = n1.(*ir.KeyExpr).Value
		case ir.OSTRUCTKEY:
			n1 = n1.(*ir.StructKeyExpr).Value
		}
		mode |= getdyn(n1, false)
		if mode == initDynamic|initConst {
			break
		}
	}
	return mode
}

// isStaticCompositeLiteral reports whether n is a compile-time constant.
func isStaticCompositeLiteral(n ir.Node) bool {
	switch n.Op() {
	case ir.OSLICELIT:
		return false
	case ir.OARRAYLIT:
		n := n.(*ir.CompLitExpr)
		for _, r := range n.List {
			if r.Op() == ir.OKEY {
				r = r.(*ir.KeyExpr).Value
			}
			if !isStaticCompositeLiteral(r) {
				return false
			}
		}
		return true
	case ir.OSTRUCTLIT:
		n := n.(*ir.CompLitExpr)
		for _, r := range n.List {
			r := r.(*ir.StructKeyExpr)
			if !isStaticCompositeLiteral(r.Value) {
				return false
			}
		}
		return true
	case ir.OLITERAL, ir.ONIL:
		return true
	case ir.OCONVIFACE:
		// See staticinit.Schedule.StaticAssign's OCONVIFACE case for comments.
		if base.Ctxt.IsFIPS() && base.Ctxt.Flag_shared {
			return false
		}
		n := n.(*ir.ConvExpr)
		val := ir.Node(n)
		for val.Op() == ir.OCONVIFACE {
			val = val.(*ir.ConvExpr).X
		}
		if val.Type().IsInterface() {
			return val.Op() == ir.ONIL
		}
		if types.IsDirectIface(val.Type()) && val.Op() == ir.ONIL {
			return true
		}
		return isStaticCompositeLiteral(val)
	}
	return false
}

// initKind is a kind of static initialization: static, dynamic, or local.
// Static initialization represents literals and
// literal components of composite literals.
// Dynamic initialization represents non-literals and
// non-literal components of composite literals.
// LocalCode initialization represents initialization
// that occurs purely in generated code local to the function of use.
// Initialization code is sometimes generated in passes,
// first static then dynamic.
type initKind uint8

const (
	initKindStatic initKind = iota + 1
	initKindDynamic
	initKindLocalCode
)

// fixedlit handles struct, array, and slice literals.
// TODO: expand documentation.
func fixedlit(ctxt initContext, kind initKind, n *ir.CompLitExpr, var_ ir.Node, init *ir.Nodes) {
	isBlank := var_ == ir.BlankNode
	var splitnode func(ir.Node) (a ir.Node, value ir.Node)
	switch n.Op() {
	case ir.OARRAYLIT, ir.OSLICELIT:
		var k int64
		splitnode = func(r ir.Node) (ir.Node, ir.Node) {
			if r.Op() == ir.OKEY {
				kv := r.(*ir.KeyExpr)
				k = typecheck.IndexConst(kv.Key)
				r = kv.Value
			}
			a := ir.NewIndexExpr(base.Pos, var_, ir.NewInt(base.Pos, k))
			k++
			if isBlank {
				return ir.BlankNode, r
			}
			return a, r
		}
	case ir.OSTRUCTLIT:
		splitnode = func(rn ir.Node) (ir.Node, ir.Node) {
			r := rn.(*ir.StructKeyExpr)
			if r.Sym().IsBlank() || isBlank {
				return ir.BlankNode, r.Value
			}
			ir.SetPos(r)
			return ir.NewSelectorExpr(base.Pos, ir.ODOT, var_, r.Sym()), r.Value
		}
	default:
		base.Fatalf("fixedlit bad op: %v", n.Op())
	}

	for _, r := range n.List {
		a, value := splitnode(r)
		if a == ir.BlankNode && !staticinit.AnySideEffects(value) {
			// Discard.
			continue
		}

		switch value.Op() {
		case ir.OSLICELIT:
			value := value.(*ir.CompLitExpr)
			if (kind == initKindStatic && ctxt == inNonInitFunction) || (kind == initKindDynamic && ctxt == inInitFunction) {
				var sinit ir.Nodes
				slicelit(ctxt, value, a, &sinit)
				if kind == initKindStatic {
					// When doing static initialization, init statements may contain dynamic
					// expression, which will be initialized later, causing liveness analysis
					// confuses about variables lifetime. So making sure those expressions
					// are ordered correctly here. See issue #52673.
					orderBlock(&sinit, map[string][]*ir.Name{})
					typecheck.Stmts(sinit)
					walkStmtList(sinit)
				}
				init.Append(sinit...)
				continue
			}

		case ir.OARRAYLIT, ir.OSTRUCTLIT:
			value := value.(*ir.CompLitExpr)
			fixedlit(ctxt, kind, value, a, init)
			continue
		}

		islit := ir.IsConstNode(value)
		if (kind == initKindStatic && !islit) || (kind == initKindDynamic && islit) {
			continue
		}

		// build list of assignments: var[index] = expr
		ir.SetPos(a)
		as := ir.NewAssignStmt(base.Pos, a, value)
		as = typecheck.Stmt(as).(*ir.AssignStmt)
		switch kind {
		case initKindStatic:
			genAsStatic(as)
		case initKindDynamic, initKindLocalCode:
			appendWalkStmt(init, orderStmtInPlace(as, map[string][]*ir.Name{}))
		default:
			base.Fatalf("fixedlit: bad kind %d", kind)
		}

	}
}

func isSmallSliceLit(n *ir.CompLitExpr) bool {
	if n.Op() != ir.OSLICELIT {
		return false
	}

	return n.Type().Elem().Size() == 0 || n.Len <= ir.MaxSmallArraySize/n.Type().Elem().Size()
}

func slicelit(ctxt initContext, n *ir.CompLitExpr, var_ ir.Node, init *ir.Nodes) {
	// make an array type corresponding the number of elements we have
	t := types.NewArray(n.Type().Elem(), n.Len)
	types.CalcSize(t)

	if ctxt == inNonInitFunction {
		// put everything into static array
		vstat := staticinit.StaticName(t)

		fixedlit(ctxt, initKindStatic, n, vstat, init)
		fixedlit(ctxt, initKindDynamic, n, vstat, init)

		// copy static to slice
		var_ = typecheck.AssignExpr(var_)
		name, offset, ok := staticinit.StaticLoc(var_)
		if !ok || name.Class != ir.PEXTERN {
			base.Fatalf("slicelit: %v", var_)
		}
		staticdata.InitSlice(name, offset, vstat.Linksym(), t.NumElem())
		return
	}

	// recipe for var = []t{...}
	// 1. make a static array
	//	var vstat [...]t
	// 2. assign (data statements) the constant part
	//	vstat = constpart{}
	// 3. make an auto pointer to array and allocate heap to it
	//	var vauto *[...]t = new([...]t)
	// 4. copy the static array to the auto array
	//	*vauto = vstat
	// 5. for each dynamic part assign to the array
	//	vauto[i] = dynamic part
	// 6. assign slice of allocated heap to var
	//	var = vauto[:]
	//
	// an optimization is done if there is no constant part
	//	3. var vauto *[...]t = new([...]t)
	//	5. vauto[i] = dynamic part
	//	6. var = vauto[:]

	// if the literal contains constants,
	// make static initialized array (1),(2)
	var vstat ir.Node

	mode := getdyn(n, true)
	if mode&initConst != 0 && !isSmallSliceLit(n) {
		if ctxt == inInitFunction {
			vstat = readonlystaticname(t)
		} else {
			vstat = staticinit.StaticName(t)
		}
		fixedlit(ctxt, initKindStatic, n, vstat, init)
	}

	// make new auto *array (3 declare)
	vauto := typecheck.TempAt(base.Pos, ir.CurFunc, types.NewPtr(t))

	// set auto to point at new temp or heap (3 assign)
	var a ir.Node
	if x := n.Prealloc; x != nil {
		// temp allocated during order.go for dddarg
		if !types.Identical(t, x.Type()) {
			panic("dotdotdot base type does not match order's assigned type")
		}
		a = initStackTemp(init, x, vstat)
	} else if n.Esc() == ir.EscNone {
		a = initStackTemp(init, typecheck.TempAt(base.Pos, ir.CurFunc, t), vstat)
	} else {
		a = ir.NewUnaryExpr(base.Pos, ir.ONEW, ir.TypeNode(t))
	}
	appendWalkStmt(init, ir.NewAssignStmt(base.Pos, vauto, a))

	if vstat != nil && n.Prealloc == nil && n.Esc() != ir.EscNone {
		// If we allocated on the heap with ONEW, copy the static to the
		// heap (4). We skip this for stack temporaries, because
		// initStackTemp already handled the copy.
		a = ir.NewStarExpr(base.Pos, vauto)
		appendWalkStmt(init, ir.NewAssignStmt(base.Pos, a, vstat))
	}

	// put dynamics into array (5)
	var index int64
	for _, value := range n.List {
		if value.Op() == ir.OKEY {
			kv := value.(*ir.KeyExpr)
			index = typecheck.IndexConst(kv.Key)
			value = kv.Value
		}
		a := ir.NewIndexExpr(base.Pos, vauto, ir.NewInt(base.Pos, index))
		a.SetBounded(true)
		index++

		// TODO need to check bounds?

		switch value.Op() {
		case ir.OSLICELIT:
			break

		case ir.OARRAYLIT, ir.OSTRUCTLIT:
			value := value.(*ir.CompLitExpr)
			k := initKindDynamic
			if vstat == nil {
				// Generate both static and dynamic initializations.
				// See issue #31987.
				k = initKindLocalCode
			}
			fixedlit(ctxt, k, value, a, init)
			continue
		}

		if vstat != nil && ir.IsConstNode(value) { // already set by copy from static value
			continue
		}

		// build list of vauto[c] = expr
		ir.SetPos(value)
		as := ir.NewAssignStmt(base.Pos, a, value)
		appendWalkStmt(init, orderStmtInPlace(typecheck.Stmt(as), map[string][]*ir.Name{}))
	}

	// make slice out of heap (6)
	a = ir.NewAssignStmt(base.Pos, var_, ir.NewSliceExpr(base.Pos, ir.OSLICE, vauto, nil, nil, nil))
	appendWalkStmt(init, orderStmtInPlace(typecheck.Stmt(a), map[string][]*ir.Name{}))
}

func maplit(n *ir.CompLitExpr, m ir.Node, init *ir.Nodes) {
	// make the map var
	args := []ir.Node{ir.TypeNode(n.Type()), ir.NewInt(base.Pos, n.Len+int64(len(n.List)))}
	a := typecheck.Expr(ir.NewCallExpr(base.Pos, ir.OMAKE, nil, args)).(*ir.MakeExpr)
	a.RType = n.RType
	a.SetEsc(n.Esc())
	appendWalkStmt(init, ir.NewAssignStmt(base.Pos, m, a))

	entries := n.List

	// The order pass already removed any dynamic (runtime-computed) entries.
	// All remaining entries are static. Double-check that.
	for _, r := range entries {
		r := r.(*ir.KeyExpr)
		if !isStaticCompositeLiteral(r.Key) || !isStaticCompositeLiteral(r.Value) {
			base.Fatalf("maplit: entry is not a literal: %v", r)
		}
	}

	if len(entries) > 25 {
		// For a large number of entries, put them in an array and loop.

		// build types [count]Tindex and [count]Tvalue
		tk := types.NewArray(n.Type().Key(), int64(len(entries)))
		te := types.NewArray(n.Type().Elem(), int64(len(entries)))

		// TODO(#47904): mark tk and te NoAlg here once the
		// compiler/linker can handle NoAlg types correctly.

		types.CalcSize(tk)
		types.CalcSize(te)

		// make and initialize static arrays
		vstatk := readonlystaticname(tk)
		vstate := readonlystaticname(te)

		datak := ir.NewCompLitExpr(base.Pos, ir.OARRAYLIT, nil, nil)
		datae := ir.NewCompLitExpr(base.Pos, ir.OARRAYLIT, nil, nil)
		for _, r := range entries {
			r := r.(*ir.KeyExpr)
			datak.List.Append(r.Key)
			datae.List.Append(r.Value)
		}
		fixedlit(inInitFunction, initKindStatic, datak, vstatk, init)
		fixedlit(inInitFunction, initKindStatic, datae, vstate, init)

		// loop adding structure elements to map
		// for i = 0; i < len(vstatk); i++ {
		//	map[vstatk[i]] = vstate[i]
		// }
		i := typecheck.TempAt(base.Pos, ir.CurFunc, types.Types[types.TINT])
		rhs := ir.NewIndexExpr(base.Pos, vstate, i)
		rhs.SetBounded(true)

		kidx := ir.NewIndexExpr(base.Pos, vstatk, i)
		kidx.SetBounded(true)

		// typechecker rewrites OINDEX to OINDEXMAP
		lhs := typecheck.AssignExpr(ir.NewIndexExpr(base.Pos, m, kidx)).(*ir.IndexExpr)
		base.AssertfAt(lhs.Op() == ir.OINDEXMAP, lhs.Pos(), "want OINDEXMAP, have %+v", lhs)
		lhs.RType = n.RType

		zero := ir.NewAssignStmt(base.Pos, i, ir.NewInt(base.Pos, 0))
		cond := ir.NewBinaryExpr(base.Pos, ir.OLT, i, ir.NewInt(base.Pos, tk.NumElem()))
		incr := ir.NewAssignStmt(base.Pos, i, ir.NewBinaryExpr(base.Pos, ir.OADD, i, ir.NewInt(base.Pos, 1)))

		var body ir.Node = ir.NewAssignStmt(base.Pos, lhs, rhs)
		body = typecheck.Stmt(body)
		body = orderStmtInPlace(body, map[string][]*ir.Name{})

		loop := ir.NewForStmt(base.Pos, nil, cond, incr, nil, false)
		loop.Body = []ir.Node{body}
		loop.SetInit([]ir.Node{zero})

		appendWalkStmt(init, loop)
		return
	}
	// For a small number of entries, just add them directly.

	// Build list of var[c] = expr.
	// Use temporaries so that mapassign1 can have addressable key, elem.
	// TODO(josharian): avoid map key temporaries for mapfast_* assignments with literal keys.
	// TODO(khr): assign these temps in order phase so we can reuse them across multiple maplits?
	tmpkey := typecheck.TempAt(base.Pos, ir.CurFunc, m.Type().Key())
	tmpelem := typecheck.TempAt(base.Pos, ir.CurFunc, m.Type().Elem())

	for _, r := range entries {
		r := r.(*ir.KeyExpr)
		index, elem := r.Key, r.Value

		ir.SetPos(index)
		appendWalkStmt(init, ir.NewAssignStmt(base.Pos, tmpkey, index))

		ir.SetPos(elem)
		appendWalkStmt(init, ir.NewAssignStmt(base.Pos, tmpelem, elem))

		ir.SetPos(tmpelem)

		// typechecker rewrites OINDEX to OINDEXMAP
		lhs := typecheck.AssignExpr(ir.NewIndexExpr(base.Pos, m, tmpkey)).(*ir.IndexExpr)
		base.AssertfAt(lhs.Op() == ir.OINDEXMAP, lhs.Pos(), "want OINDEXMAP, have %+v", lhs)
		lhs.RType = n.RType

		var a ir.Node = ir.NewAssignStmt(base.Pos, lhs, tmpelem)
		a = typecheck.Stmt(a)
		a = orderStmtInPlace(a, map[string][]*ir.Name{})
		appendWalkStmt(init, a)
	}
}

func anylit(n ir.Node, var_ ir.Node, init *ir.Nodes) {
	t := n.Type()
	switch n.Op() {
	default:
		base.Fatalf("anylit: not lit, op=%v node=%v", n.Op(), n)

	case ir.ONAME:
		n := n.(*ir.Name)
		appendWalkStmt(init, ir.NewAssignStmt(base.Pos, var_, n))

	case ir.OMETHEXPR:
		n := n.(*ir.SelectorExpr)
		anylit(n.FuncName(), var_, init)

	case ir.OPTRLIT:
		n := n.(*ir.AddrExpr)
		if !t.IsPtr() {
			base.Fatalf("anylit: not ptr")
		}

		var r ir.Node
		if n.Prealloc != nil {
			// n.Prealloc is stack temporary used as backing store.
			r = initStackTemp(init, n.Prealloc, nil)
		} else {
			r = ir.NewUnaryExpr(base.Pos, ir.ONEW, ir.TypeNode(n.X.Type()))
			r.SetEsc(n.Esc())
		}
		appendWalkStmt(init, ir.NewAssignStmt(base.Pos, var_, r))

		var_ = ir.NewStarExpr(base.Pos, var_)
		var_ = typecheck.AssignExpr(var_)
		anylit(n.X, var_, init)

	case ir.OSTRUCTLIT, ir.OARRAYLIT:
		n := n.(*ir.CompLitExpr)
		if !t.IsStruct() && !t.IsArray() {
			base.Fatalf("anylit: not struct/array")
		}

		if isSimpleName(var_) && len(n.List) > 4 {
			// lay out static data
			vstat := readonlystaticname(t)

			ctxt := inInitFunction
			if n.Op() == ir.OARRAYLIT {
				ctxt = inNonInitFunction
			}
			fixedlit(ctxt, initKindStatic, n, vstat, init)

			// copy static to var
			appendWalkStmt(init, ir.NewAssignStmt(base.Pos, var_, vstat))

			// add expressions to automatic
			fixedlit(inInitFunction, initKindDynamic, n, var_, init)
			break
		}

		var components int64
		if n.Op() == ir.OARRAYLIT {
			components = t.NumElem()
		} else {
			components = int64(t.NumFields())
		}
		// initialization of an array or struct with unspecified components (missing fields or arrays)
		if isSimpleName(var_) || int64(len(n.List)) < components {
			appendWalkStmt(init, ir.NewAssignStmt(base.Pos, var_, nil))
		}

		fixedlit(inInitFunction, initKindLocalCode, n, var_, init)

	case ir.OSLICELIT:
		n := n.(*ir.CompLitExpr)
		slicelit(inInitFunction, n, var_, init)

	case ir.OMAPLIT:
		n := n.(*ir.CompLitExpr)
		if !t.IsMap() {
			base.Fatalf("anylit: not map")
		}
		maplit(n, var_, init)
	}
}

// oaslit handles special composite literal assignments.
// It returns true if n's effects have been added to init,
// in which case n should be dropped from the program by the caller.
func oaslit(n *ir.AssignStmt, init *ir.Nodes) bool {
	if n.X == nil || n.Y == nil {
		// not a special composite literal assignment
		return false
	}
	if n.X.Type() == nil || n.Y.Type() == nil {
		// not a special composite literal assignment
		return false
	}
	if !isSimpleName(n.X) {
		// not a special composite literal assignment
		return false
	}
	x := n.X.(*ir.Name)
	if !types.Identical(n.X.Type(), n.Y.Type()) {
		// not a special composite literal assignment
		return false
	}
	if x.Addrtaken() {
		// If x is address-taken, the RHS may (implicitly) uses LHS.
		// Not safe to do a special composite literal assignment
		// (which may expand to multiple assignments).
		return false
	}

	switch n.Y.Op() {
	default:
		// not a special composite literal assignment
		return false

	case ir.OSTRUCTLIT, ir.OARRAYLIT, ir.OSLICELIT, ir.OMAPLIT:
		if ir.Any(n.Y, func(y ir.Node) bool { return ir.Uses(y, x) }) {
			// not safe to do a special composite literal assignment if RHS uses LHS.
			return false
		}
		anylit(n.Y, n.X, init)
	}

	return true
}

func genAsStatic(as *ir.AssignStmt) {
	if as.X.Type() == nil {
		base.Fatalf("genAsStatic as.Left not typechecked")
	}

	name, offset, ok := staticinit.StaticLoc(as.X)
	if !ok || (name.Class != ir.PEXTERN && as.X != ir.BlankNode) {
		base.Fatalf("genAsStatic: lhs %v", as.X)
	}

	switch r := as.Y; r.Op() {
	case ir.OLITERAL:
		staticdata.InitConst(name, offset, r, int(r.Type().Size()))
		return
	case ir.OMETHEXPR:
		r := r.(*ir.SelectorExpr)
		staticdata.InitAddr(name, offset, staticdata.FuncLinksym(r.FuncName()))
		return
	case ir.ONAME:
		r := r.(*ir.Name)
		if r.Offset_ != 0 {
			base.Fatalf("genAsStatic %+v", as)
		}
		if r.Class == ir.PFUNC {
			staticdata.InitAddr(name, offset, staticdata.FuncLinksym(r))
			return
		}
	}
	base.Fatalf("genAsStatic: rhs %v", as.Y)
}

"""



```