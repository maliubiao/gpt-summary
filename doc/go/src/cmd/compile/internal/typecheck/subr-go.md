Response:
My thinking process to analyze the Go code snippet and generate the response involved several steps:

1. **Initial Scan and Keyword Spotting:** I first scanned the code for familiar Go keywords and package names. I noticed imports like `cmd/compile/internal/ir`, `cmd/compile/internal/types`, `cmd/internal/obj`, and `cmd/internal/src`, which strongly suggested this code is part of the Go compiler. The package name `typecheck` further reinforces this. Function names like `AssignConv`, `LookupNum`, `NewFuncParams`, `NodAddr`, `CalcMethods`, `Implements`, and `convertOp` hinted at core type-checking and conversion functionalities.

2. **Deconstructing Function by Function:**  I then went through each function, trying to understand its purpose based on its name, parameters, return values, and internal logic.

    * **Simple Functions First:**  I started with simpler functions like `LookupNum` (clearly a wrapper for looking up symbols), `NewFuncParams` (creating new field lists), `NodAddr` (creating address expressions), and `NodNil` (creating a nil expression). These were relatively straightforward.

    * **Type Conversion and Assignment:**  Functions like `AssignConv`, `assignOp`, and `convertOp` immediately stood out as crucial for type checking and conversion. I noted the `ir.Op` return type, suggesting they return the kind of conversion needed. The logic within these functions involving `types.Identical`, `types.Underlying`, and checks for interface implementation was key.

    * **Method Resolution and Embedding:**  `AddImplicitDots`, `CalcMethods`, `adddot1`, and `dotpath` seemed related to resolving method calls on embedded structs and interfaces. The concepts of "implicit dots" and finding the "shortest unique addressing" were interesting clues. The `expand0` and `expand1` functions appeared to be recursive methods for discovering accessible methods.

    * **Interface Implementation:**  `Implements` and `ImplementsExplain` were clearly focused on determining if a type satisfies an interface. The detailed explanations in `ImplementsExplain` suggested it's used for generating informative error messages.

3. **Identifying Core Functionality:**  By analyzing the individual functions, I started to see the broader picture. The code primarily deals with:

    * **Type Conversions:**  Ensuring valid conversions between different Go types, including implicit conversions during assignment and explicit conversions.
    * **Method Resolution:**  Finding the correct method to call, especially when dealing with embedded structs and interfaces, including handling implicit field access.
    * **Interface Implementation Checking:**  Verifying if a given type fulfills the requirements of an interface.
    * **Node Creation:**  Generating intermediate representation (IR) nodes for expressions like addresses and conversions.
    * **Symbol Lookup:**  Finding type and other symbols within the program.

4. **Inferring Go Language Features:** Based on the identified functionalities, I could infer the corresponding Go language features being implemented:

    * **Type Compatibility and Conversion Rules:** The `assignOp` and `convertOp` functions directly implement Go's rules for type assignment and conversion.
    * **Embedded Structs and Interfaces:** The functions related to "implicit dots" and method resolution handle the way Go allows accessing fields and methods of embedded types.
    * **Interface Satisfaction:** The `Implements` functions implement Go's core concept of interfaces and how types satisfy them.
    * **Address Operator (&):** `NodAddr` directly relates to the address-of operator.
    * **Nil Value:** `NodNil` handles the representation of the `nil` value.

5. **Crafting Examples:** To illustrate the inferred functionalities, I created Go code examples. For type conversion, I showed both valid and invalid assignment scenarios. For embedded structs, I demonstrated accessing fields and methods through implicit embedding. For interfaces, I showed a type implementing an interface and the resulting behavior.

6. **Considering Corner Cases and Potential Errors:**  I thought about potential pitfalls for users, specifically related to type conversions and the subtleties of interface satisfaction (e.g., pointer receivers).

7. **Structuring the Response:** Finally, I organized the information into a clear and logical structure, addressing each part of the prompt:

    * **Functionality List:** A concise summary of the main purposes of the code.
    * **Go Language Feature Implementation:** Mapping the code to specific Go language features.
    * **Code Examples:** Demonstrating the functionality with concrete Go code snippets.
    * **Assumptions and Inputs/Outputs (where applicable):** Providing context for code examples that involved more complex logic (like implicit dots).
    * **Command-Line Parameters:** Noting the absence of command-line parameter handling.
    * **Common Mistakes:**  Highlighting potential errors users might make.

This iterative process of scanning, analyzing, inferring, and illustrating allowed me to generate a comprehensive and accurate response to the prompt. The initial focus on identifying key functions and their purpose was crucial for understanding the overall functionality of the code snippet.
这段代码是 Go 编译器 `cmd/compile/internal/typecheck` 包中的 `subr.go` 文件的一部分，主要提供了一些辅助函数，用于类型检查阶段的各种操作。  从代码的功能来看，它主要围绕着 **类型转换**、**方法查找**、**接口实现检查** 以及 **构建抽象语法树节点** 这几个核心方面展开。

下面列举一下它的主要功能，并尝试推理它所实现的 Go 语言功能：

**1. 类型转换相关:**

* **`AssignConv(n ir.Node, t *types.Type, context string) ir.Node` 和 `assignconvfn(n ir.Node, t *types.Type, context func() string) ir.Node`:** 这两个函数用于将一个表达式 `n` 转换为类型 `t`，用于赋值操作。`AssignConv` 是一个便捷的包装器。`assignconvfn` 内部会调用 `convlit1`（未在此代码段中），处理字面量转换，然后调用 `assignOp` 判断是否可以进行赋值转换，如果可以则生成相应的转换操作节点（如 `OCONV`, `OCONVIFACE` 等）。
    * **推测实现的 Go 语言功能:**  Go 语言中的 **隐式类型转换** (在赋值场景下) 和 **类型断言** (在赋值给接口类型时)。

    ```go
    package main

    type MyInt int
    type MyString string

    func main() {
        var i int = 10
        var myInt MyInt = i // 错误: cannot use i (variable of type int) as MyInt value in assignment

        var j int = MyInt(5) // 正确: 显式类型转换

        var s string = "hello"
        var myString MyString = s // 错误: cannot use s (variable of type string) as MyString value in assignment

        var t interface{} = i
        var k int = t.(int) // 类型断言

        // 假设输入: n 是一个代表整数 10 的 ir.Node, t 是 *types.Type 代表 MyInt 类型
        // 假设输出: 一个表示将整数 10 转换为 MyInt 的 ir.Node，其操作码可能是 OCONV。
    }
    ```

* **`assignOp(src, dst *types.Type) (ir.Op, string)`:**  判断类型 `src` 的值是否可以赋值给类型 `dst`。如果可以，返回相应的转换操作码 (`ir.Op`)，否则返回 `ir.OXXX` 并可能提供错误原因。
    * **推测实现的 Go 语言功能:**  Go 语言的 **赋值兼容性规则**。

* **`convertOp(srcConstant bool, src, dst *types.Type) (ir.Op, string)`:**  判断类型 `src` 的值是否可以转换为类型 `dst`。与 `assignOp` 类似，但考虑了更广泛的转换场景，包括显式类型转换。`srcConstant` 表示源类型是否是常量。
    * **推测实现的 Go 语言功能:** Go 语言的 **显式类型转换规则**。

    ```go
    package main

    import "fmt"

    func main() {
        var f float64 = 3.14
        var i int = int(f) // 显式将 float64 转换为 int
        fmt.Println(i) // 输出: 3

        var s string = "123"
        // var num int = int(s) // 错误: cannot convert s (type string) to type int

        // 假设输入: src 是 *types.Type 代表 float64, dst 是 *types.Type 代表 int
        // 假设输出: ir.OCONV, "" 表示可以进行转换。
    }
    ```

**2. 方法查找和隐式点号:**

* **`AddImplicitDots(n *ir.SelectorExpr) *ir.SelectorExpr`:**  用于处理结构体嵌套时的隐式字段访问（省略中间的字段名）。它会找到最短的唯一寻址路径，并在语法树中补全省略的点号。
    * **推测实现的 Go 语言功能:** Go 语言中 **访问嵌套结构体字段时可以省略中间唯一可确定的字段名** 的特性。

    ```go
    package main

    type A struct {
        B
    }

    type B struct {
        C
    }

    type C struct {
        Value int
    }

    func main() {
        a := A{B: B{C: C{Value: 10}}}
        println(a.Value) // 可以直接访问 a.Value，即使中间有 B 和 C
        // 假设输入: n 是代表 a.Value 的 *ir.SelectorExpr, a 的类型是 *types.Type 代表 A
        // 假设输出: 修改后的 n，其结构类似 a.B.C.Value 的 ir.Node 结构。
    }
    ```

* **`CalcMethods(t *types.Type)`:** 计算类型 `t` 的所有方法，包括通过嵌入获得的方法。
    * **推测实现的 Go 语言功能:** Go 语言中 **通过嵌入类型来继承方法** 的特性。

* **`dotpath(s *types.Sym, t *types.Type, save **types.Field, ignorecase bool) (path []dlist, ambig bool)` 和 `adddot1(s *types.Sym, t *types.Type, d int, save **types.Field, ignorecase bool) (c int, more bool)`:** 这两个函数一起用于查找类型 `t` 中名为 `s` 的字段或方法，并构建访问路径（用于 `AddImplicitDots`）。`dotpath` 是入口，`adddot1` 负责递归查找。
* **`lookdot0(s *types.Sym, t *types.Type, save **types.Field, ignorecase bool) int`:**  查找类型 `t` 中名为 `s` 的字段或方法的数量。
* **`expand0(t *types.Type)` 和 `expand1(t *types.Type, top bool)`:**  用于展开类型 `t` 的方法列表，包括嵌入的方法。

**3. 接口实现检查:**

* **`Implements(t, iface *types.Type) bool`:**  判断类型 `t` 是否实现了接口 `iface`。
    * **推测实现的 Go 语言功能:** Go 语言的 **接口实现机制**。

* **`ImplementsExplain(t, iface *types.Type) string`:**  判断类型 `t` 是否实现了接口 `iface`，如果未实现，则返回解释原因的字符串。
    * **推测实现的 Go 语言功能:**  Go 语言编译器在 **类型检查时判断接口实现并给出错误提示** 的功能。

* **`implements(t, iface *types.Type, m, samename **types.Field, ptr *int) bool`:** `Implements` 和 `ImplementsExplain` 的核心实现。它会比较类型 `t` 的方法集合和接口 `iface` 的方法集合。

* **`ifacelookdot(s *types.Sym, t *types.Type, ignorecase bool) *types.Field`:** 在接口类型 `t` 中查找名为 `s` 的方法。

**4. 其他辅助功能:**

* **`LookupNum(prefix string, n int) *types.Sym`:**  调用 `types.LocalPkg.LookupNum`，用于查找带有数字后缀的符号。
* **`NewFuncParams(origs []*types.Field) []*types.Field`:**  创建一个新的函数参数字段列表，复制原始字段的信息。
* **`NodAddr(n ir.Node) *ir.AddrExpr` 和 `NodAddrAt(pos src.XPos, n ir.Node) *ir.AddrExpr`:**  创建表示取地址操作 (`&`) 的抽象语法树节点 (`ir.AddrExpr`)。
    * **推测实现的 Go 语言功能:** Go 语言的 **取地址运算符 `&`**。

    ```go
    package main

    func main() {
        i := 10
        ptr := &i // 取 i 的地址
        println(ptr)

        // 假设输入: n 是代表变量 i 的 ir.Node
        // 假设输出: 一个表示 &i 的 ir.AddrExpr 节点。
    }
    ```

* **`LinksymAddr(pos src.XPos, lsym *obj.LSym, typ *types.Type) *ir.AddrExpr`:**  创建一个表示链接符号地址的表达式。
* **`NodNil() ir.Node`:**  创建一个表示 `nil` 值的抽象语法树节点 (`ir.NilExpr`)。
    * **推测实现的 Go 语言功能:** Go 语言的 **`nil` 值**。

**没有涉及到的功能:**

这段代码没有直接处理命令行参数。它主要关注类型检查内部的逻辑。命令行参数的处理通常在编译器的其他阶段进行。

**使用者易犯错的点（开发者编写 Go 代码时）:**

虽然这段代码是编译器内部的实现，但理解其背后的逻辑可以帮助 Go 开发者避免一些常见的错误：

1. **类型转换错误:**  不理解 Go 的类型转换规则，尝试进行不合法的类型转换，例如将字符串直接转换为整数，或者在没有实现接口的情况下将类型赋值给接口变量。`assignOp` 和 `convertOp` 的逻辑反映了这些规则。

2. **接口理解不足:**  不清楚一个类型是否实现了某个接口，导致类型断言失败或者在需要接口的地方使用了不兼容的类型。`Implements` 和 `ImplementsExplain` 的逻辑可以帮助理解接口实现的条件。

3. **对嵌入理解不足:**  不了解通过嵌入获得方法和字段的规则，可能导致访问嵌入字段时出现歧义或错误。`AddImplicitDots` 和 `CalcMethods` 的逻辑与此相关。

**总结:**

`subr.go` 中的这部分代码是 Go 编译器类型检查阶段的关键组成部分，它实现了类型转换、方法查找、接口实现检查等核心功能，确保了 Go 程序的类型安全性。理解这些底层的实现逻辑有助于更深入地理解 Go 语言的类型系统和编译过程，并避免在编写 Go 代码时犯一些常见的类型相关的错误。

### 提示词
```
这是路径为go/src/cmd/compile/internal/typecheck/subr.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package typecheck

import (
	"fmt"
	"slices"
	"strings"

	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/src"
)

func AssignConv(n ir.Node, t *types.Type, context string) ir.Node {
	return assignconvfn(n, t, func() string { return context })
}

// LookupNum returns types.LocalPkg.LookupNum(prefix, n).
func LookupNum(prefix string, n int) *types.Sym {
	return types.LocalPkg.LookupNum(prefix, n)
}

// Given funarg struct list, return list of fn args.
func NewFuncParams(origs []*types.Field) []*types.Field {
	res := make([]*types.Field, len(origs))
	for i, orig := range origs {
		p := types.NewField(orig.Pos, orig.Sym, orig.Type)
		p.SetIsDDD(orig.IsDDD())
		res[i] = p
	}
	return res
}

// NodAddr returns a node representing &n at base.Pos.
func NodAddr(n ir.Node) *ir.AddrExpr {
	return NodAddrAt(base.Pos, n)
}

// NodAddrAt returns a node representing &n at position pos.
func NodAddrAt(pos src.XPos, n ir.Node) *ir.AddrExpr {
	return ir.NewAddrExpr(pos, Expr(n))
}

// LinksymAddr returns a new expression that evaluates to the address
// of lsym. typ specifies the type of the addressed memory.
func LinksymAddr(pos src.XPos, lsym *obj.LSym, typ *types.Type) *ir.AddrExpr {
	n := ir.NewLinksymExpr(pos, lsym, typ)
	return Expr(NodAddrAt(pos, n)).(*ir.AddrExpr)
}

func NodNil() ir.Node {
	return ir.NewNilExpr(base.Pos, types.Types[types.TNIL])
}

// AddImplicitDots finds missing fields in obj.field that
// will give the shortest unique addressing and
// modifies the tree with missing field names.
func AddImplicitDots(n *ir.SelectorExpr) *ir.SelectorExpr {
	n.X = typecheck(n.X, ctxType|ctxExpr)
	t := n.X.Type()
	if t == nil {
		return n
	}

	if n.X.Op() == ir.OTYPE {
		return n
	}

	s := n.Sel
	if s == nil {
		return n
	}

	switch path, ambig := dotpath(s, t, nil, false); {
	case path != nil:
		// rebuild elided dots
		for c := len(path) - 1; c >= 0; c-- {
			dot := ir.NewSelectorExpr(n.Pos(), ir.ODOT, n.X, path[c].field.Sym)
			dot.SetImplicit(true)
			dot.SetType(path[c].field.Type)
			n.X = dot
		}
	case ambig:
		base.Errorf("ambiguous selector %v", n)
		n.X = nil
	}

	return n
}

// CalcMethods calculates all the methods (including embedding) of a non-interface
// type t.
func CalcMethods(t *types.Type) {
	if t == nil || len(t.AllMethods()) != 0 {
		return
	}

	// mark top-level method symbols
	// so that expand1 doesn't consider them.
	for _, f := range t.Methods() {
		f.Sym.SetUniq(true)
	}

	// generate all reachable methods
	slist = slist[:0]
	expand1(t, true)

	// check each method to be uniquely reachable
	var ms []*types.Field
	for i, sl := range slist {
		slist[i].field = nil
		sl.field.Sym.SetUniq(false)

		var f *types.Field
		path, _ := dotpath(sl.field.Sym, t, &f, false)
		if path == nil {
			continue
		}

		// dotpath may have dug out arbitrary fields, we only want methods.
		if !f.IsMethod() {
			continue
		}

		// add it to the base type method list
		f = f.Copy()
		f.Embedded = 1 // needs a trampoline
		for _, d := range path {
			if d.field.Type.IsPtr() {
				f.Embedded = 2
				break
			}
		}
		ms = append(ms, f)
	}

	for _, f := range t.Methods() {
		f.Sym.SetUniq(false)
	}

	ms = append(ms, t.Methods()...)
	slices.SortFunc(ms, types.CompareFields)
	t.SetAllMethods(ms)
}

// adddot1 returns the number of fields or methods named s at depth d in Type t.
// If exactly one exists, it will be returned in *save (if save is not nil),
// and dotlist will contain the path of embedded fields traversed to find it,
// in reverse order. If none exist, more will indicate whether t contains any
// embedded fields at depth d, so callers can decide whether to retry at
// a greater depth.
func adddot1(s *types.Sym, t *types.Type, d int, save **types.Field, ignorecase bool) (c int, more bool) {
	if t.Recur() {
		return
	}
	t.SetRecur(true)
	defer t.SetRecur(false)

	var u *types.Type
	d--
	if d < 0 {
		// We've reached our target depth. If t has any fields/methods
		// named s, then we're done. Otherwise, we still need to check
		// below for embedded fields.
		c = lookdot0(s, t, save, ignorecase)
		if c != 0 {
			return c, false
		}
	}

	u = t
	if u.IsPtr() {
		u = u.Elem()
	}
	if !u.IsStruct() && !u.IsInterface() {
		return c, false
	}

	var fields []*types.Field
	if u.IsStruct() {
		fields = u.Fields()
	} else {
		fields = u.AllMethods()
	}
	for _, f := range fields {
		if f.Embedded == 0 || f.Sym == nil {
			continue
		}
		if d < 0 {
			// Found an embedded field at target depth.
			return c, true
		}
		a, more1 := adddot1(s, f.Type, d, save, ignorecase)
		if a != 0 && c == 0 {
			dotlist[d].field = f
		}
		c += a
		if more1 {
			more = true
		}
	}

	return c, more
}

// dotlist is used by adddot1 to record the path of embedded fields
// used to access a target field or method.
// Must be non-nil so that dotpath returns a non-nil slice even if d is zero.
var dotlist = make([]dlist, 10)

// Convert node n for assignment to type t.
func assignconvfn(n ir.Node, t *types.Type, context func() string) ir.Node {
	if n == nil || n.Type() == nil {
		return n
	}

	if t.Kind() == types.TBLANK && n.Type().Kind() == types.TNIL {
		base.Errorf("use of untyped nil")
	}

	n = convlit1(n, t, false, context)
	if n.Type() == nil {
		base.Fatalf("cannot assign %v to %v", n, t)
	}
	if n.Type().IsUntyped() {
		base.Fatalf("%L has untyped type", n)
	}
	if t.Kind() == types.TBLANK {
		return n
	}
	if types.Identical(n.Type(), t) {
		return n
	}

	op, why := assignOp(n.Type(), t)
	if op == ir.OXXX {
		base.Errorf("cannot use %L as type %v in %s%s", n, t, context(), why)
		op = ir.OCONV
	}

	r := ir.NewConvExpr(base.Pos, op, t, n)
	r.SetTypecheck(1)
	r.SetImplicit(true)
	return r
}

// Is type src assignment compatible to type dst?
// If so, return op code to use in conversion.
// If not, return OXXX. In this case, the string return parameter may
// hold a reason why. In all other cases, it'll be the empty string.
func assignOp(src, dst *types.Type) (ir.Op, string) {
	if src == dst {
		return ir.OCONVNOP, ""
	}
	if src == nil || dst == nil || src.Kind() == types.TFORW || dst.Kind() == types.TFORW || src.Underlying() == nil || dst.Underlying() == nil {
		return ir.OXXX, ""
	}

	// 1. src type is identical to dst.
	if types.Identical(src, dst) {
		return ir.OCONVNOP, ""
	}

	// 2. src and dst have identical underlying types and
	//   a. either src or dst is not a named type, or
	//   b. both are empty interface types, or
	//   c. at least one is a gcshape type.
	// For assignable but different non-empty interface types,
	// we want to recompute the itab. Recomputing the itab ensures
	// that itabs are unique (thus an interface with a compile-time
	// type I has an itab with interface type I).
	if types.Identical(src.Underlying(), dst.Underlying()) {
		if src.IsEmptyInterface() {
			// Conversion between two empty interfaces
			// requires no code.
			return ir.OCONVNOP, ""
		}
		if (src.Sym() == nil || dst.Sym() == nil) && !src.IsInterface() {
			// Conversion between two types, at least one unnamed,
			// needs no conversion. The exception is nonempty interfaces
			// which need to have their itab updated.
			return ir.OCONVNOP, ""
		}
		if src.IsShape() || dst.IsShape() {
			// Conversion between a shape type and one of the types
			// it represents also needs no conversion.
			return ir.OCONVNOP, ""
		}
	}

	// 3. dst is an interface type and src implements dst.
	if dst.IsInterface() && src.Kind() != types.TNIL {
		if src.IsShape() {
			// Shape types implement things they have already
			// been typechecked to implement, even if they
			// don't have the methods for them.
			return ir.OCONVIFACE, ""
		}
		if src.HasShape() {
			// Unified IR uses OCONVIFACE for converting all derived types
			// to interface type, not just type arguments themselves.
			return ir.OCONVIFACE, ""
		}

		why := ImplementsExplain(src, dst)
		if why == "" {
			return ir.OCONVIFACE, ""
		}
		return ir.OXXX, ":\n\t" + why
	}

	if isptrto(dst, types.TINTER) {
		why := fmt.Sprintf(":\n\t%v is pointer to interface, not interface", dst)
		return ir.OXXX, why
	}

	if src.IsInterface() && dst.Kind() != types.TBLANK {
		var why string
		if Implements(dst, src) {
			why = ": need type assertion"
		}
		return ir.OXXX, why
	}

	// 4. src is a bidirectional channel value, dst is a channel type,
	// src and dst have identical element types, and
	// either src or dst is not a named type.
	if src.IsChan() && src.ChanDir() == types.Cboth && dst.IsChan() {
		if types.Identical(src.Elem(), dst.Elem()) && (src.Sym() == nil || dst.Sym() == nil) {
			return ir.OCONVNOP, ""
		}
	}

	// 5. src is the predeclared identifier nil and dst is a nillable type.
	if src.Kind() == types.TNIL {
		switch dst.Kind() {
		case types.TPTR,
			types.TFUNC,
			types.TMAP,
			types.TCHAN,
			types.TINTER,
			types.TSLICE:
			return ir.OCONVNOP, ""
		}
	}

	// 6. rule about untyped constants - already converted by DefaultLit.

	// 7. Any typed value can be assigned to the blank identifier.
	if dst.Kind() == types.TBLANK {
		return ir.OCONVNOP, ""
	}

	return ir.OXXX, ""
}

// Can we convert a value of type src to a value of type dst?
// If so, return op code to use in conversion (maybe OCONVNOP).
// If not, return OXXX. In this case, the string return parameter may
// hold a reason why. In all other cases, it'll be the empty string.
// srcConstant indicates whether the value of type src is a constant.
func convertOp(srcConstant bool, src, dst *types.Type) (ir.Op, string) {
	if src == dst {
		return ir.OCONVNOP, ""
	}
	if src == nil || dst == nil {
		return ir.OXXX, ""
	}

	// Conversions from regular to not-in-heap are not allowed
	// (unless it's unsafe.Pointer). These are runtime-specific
	// rules.
	// (a) Disallow (*T) to (*U) where T is not-in-heap but U isn't.
	if src.IsPtr() && dst.IsPtr() && dst.Elem().NotInHeap() && !src.Elem().NotInHeap() {
		why := fmt.Sprintf(":\n\t%v is incomplete (or unallocatable), but %v is not", dst.Elem(), src.Elem())
		return ir.OXXX, why
	}
	// (b) Disallow string to []T where T is not-in-heap.
	if src.IsString() && dst.IsSlice() && dst.Elem().NotInHeap() && (dst.Elem().Kind() == types.ByteType.Kind() || dst.Elem().Kind() == types.RuneType.Kind()) {
		why := fmt.Sprintf(":\n\t%v is incomplete (or unallocatable)", dst.Elem())
		return ir.OXXX, why
	}

	// 1. src can be assigned to dst.
	op, why := assignOp(src, dst)
	if op != ir.OXXX {
		return op, why
	}

	// The rules for interfaces are no different in conversions
	// than assignments. If interfaces are involved, stop now
	// with the good message from assignop.
	// Otherwise clear the error.
	if src.IsInterface() || dst.IsInterface() {
		return ir.OXXX, why
	}

	// 2. Ignoring struct tags, src and dst have identical underlying types.
	if types.IdenticalIgnoreTags(src.Underlying(), dst.Underlying()) {
		return ir.OCONVNOP, ""
	}

	// 3. src and dst are unnamed pointer types and, ignoring struct tags,
	// their base types have identical underlying types.
	if src.IsPtr() && dst.IsPtr() && src.Sym() == nil && dst.Sym() == nil {
		if types.IdenticalIgnoreTags(src.Elem().Underlying(), dst.Elem().Underlying()) {
			return ir.OCONVNOP, ""
		}
	}

	// 4. src and dst are both integer or floating point types.
	if (src.IsInteger() || src.IsFloat()) && (dst.IsInteger() || dst.IsFloat()) {
		if types.SimType[src.Kind()] == types.SimType[dst.Kind()] {
			return ir.OCONVNOP, ""
		}
		return ir.OCONV, ""
	}

	// 5. src and dst are both complex types.
	if src.IsComplex() && dst.IsComplex() {
		if types.SimType[src.Kind()] == types.SimType[dst.Kind()] {
			return ir.OCONVNOP, ""
		}
		return ir.OCONV, ""
	}

	// Special case for constant conversions: any numeric
	// conversion is potentially okay. We'll validate further
	// within evconst. See #38117.
	if srcConstant && (src.IsInteger() || src.IsFloat() || src.IsComplex()) && (dst.IsInteger() || dst.IsFloat() || dst.IsComplex()) {
		return ir.OCONV, ""
	}

	// 6. src is an integer or has type []byte or []rune
	// and dst is a string type.
	if src.IsInteger() && dst.IsString() {
		return ir.ORUNESTR, ""
	}

	if src.IsSlice() && dst.IsString() {
		if src.Elem().Kind() == types.ByteType.Kind() {
			return ir.OBYTES2STR, ""
		}
		if src.Elem().Kind() == types.RuneType.Kind() {
			return ir.ORUNES2STR, ""
		}
	}

	// 7. src is a string and dst is []byte or []rune.
	// String to slice.
	if src.IsString() && dst.IsSlice() {
		if dst.Elem().Kind() == types.ByteType.Kind() {
			return ir.OSTR2BYTES, ""
		}
		if dst.Elem().Kind() == types.RuneType.Kind() {
			return ir.OSTR2RUNES, ""
		}
	}

	// 8. src is a pointer or uintptr and dst is unsafe.Pointer.
	if (src.IsPtr() || src.IsUintptr()) && dst.IsUnsafePtr() {
		return ir.OCONVNOP, ""
	}

	// 9. src is unsafe.Pointer and dst is a pointer or uintptr.
	if src.IsUnsafePtr() && (dst.IsPtr() || dst.IsUintptr()) {
		return ir.OCONVNOP, ""
	}

	// 10. src is a slice and dst is an array or pointer-to-array.
	// They must have same element type.
	if src.IsSlice() {
		if dst.IsArray() && types.Identical(src.Elem(), dst.Elem()) {
			return ir.OSLICE2ARR, ""
		}
		if dst.IsPtr() && dst.Elem().IsArray() &&
			types.Identical(src.Elem(), dst.Elem().Elem()) {
			return ir.OSLICE2ARRPTR, ""
		}
	}

	return ir.OXXX, ""
}

// Code to resolve elided DOTs in embedded types.

// A dlist stores a pointer to a TFIELD Type embedded within
// a TSTRUCT or TINTER Type.
type dlist struct {
	field *types.Field
}

// dotpath computes the unique shortest explicit selector path to fully qualify
// a selection expression x.f, where x is of type t and f is the symbol s.
// If no such path exists, dotpath returns nil.
// If there are multiple shortest paths to the same depth, ambig is true.
func dotpath(s *types.Sym, t *types.Type, save **types.Field, ignorecase bool) (path []dlist, ambig bool) {
	// The embedding of types within structs imposes a tree structure onto
	// types: structs parent the types they embed, and types parent their
	// fields or methods. Our goal here is to find the shortest path to
	// a field or method named s in the subtree rooted at t. To accomplish
	// that, we iteratively perform depth-first searches of increasing depth
	// until we either find the named field/method or exhaust the tree.
	for d := 0; ; d++ {
		if d > len(dotlist) {
			dotlist = append(dotlist, dlist{})
		}
		if c, more := adddot1(s, t, d, save, ignorecase); c == 1 {
			return dotlist[:d], false
		} else if c > 1 {
			return nil, true
		} else if !more {
			return nil, false
		}
	}
}

func expand0(t *types.Type) {
	u := t
	if u.IsPtr() {
		u = u.Elem()
	}

	if u.IsInterface() {
		for _, f := range u.AllMethods() {
			if f.Sym.Uniq() {
				continue
			}
			f.Sym.SetUniq(true)
			slist = append(slist, symlink{field: f})
		}

		return
	}

	u = types.ReceiverBaseType(t)
	if u != nil {
		for _, f := range u.Methods() {
			if f.Sym.Uniq() {
				continue
			}
			f.Sym.SetUniq(true)
			slist = append(slist, symlink{field: f})
		}
	}
}

func expand1(t *types.Type, top bool) {
	if t.Recur() {
		return
	}
	t.SetRecur(true)

	if !top {
		expand0(t)
	}

	u := t
	if u.IsPtr() {
		u = u.Elem()
	}

	if u.IsStruct() || u.IsInterface() {
		var fields []*types.Field
		if u.IsStruct() {
			fields = u.Fields()
		} else {
			fields = u.AllMethods()
		}
		for _, f := range fields {
			if f.Embedded == 0 {
				continue
			}
			if f.Sym == nil {
				continue
			}
			expand1(f.Type, false)
		}
	}

	t.SetRecur(false)
}

func ifacelookdot(s *types.Sym, t *types.Type, ignorecase bool) *types.Field {
	if t == nil {
		return nil
	}

	var m *types.Field
	path, _ := dotpath(s, t, &m, ignorecase)
	if path == nil {
		return nil
	}

	if !m.IsMethod() {
		return nil
	}

	return m
}

// Implements reports whether t implements the interface iface. t can be
// an interface, a type parameter, or a concrete type.
func Implements(t, iface *types.Type) bool {
	var missing, have *types.Field
	var ptr int
	return implements(t, iface, &missing, &have, &ptr)
}

// ImplementsExplain reports whether t implements the interface iface. t can be
// an interface, a type parameter, or a concrete type. If t does not implement
// iface, a non-empty string is returned explaining why.
func ImplementsExplain(t, iface *types.Type) string {
	var missing, have *types.Field
	var ptr int
	if implements(t, iface, &missing, &have, &ptr) {
		return ""
	}

	if isptrto(t, types.TINTER) {
		return fmt.Sprintf("%v is pointer to interface, not interface", t)
	} else if have != nil && have.Sym == missing.Sym && have.Nointerface() {
		return fmt.Sprintf("%v does not implement %v (%v method is marked 'nointerface')", t, iface, missing.Sym)
	} else if have != nil && have.Sym == missing.Sym {
		return fmt.Sprintf("%v does not implement %v (wrong type for %v method)\n"+
			"\t\thave %v%S\n\t\twant %v%S", t, iface, missing.Sym, have.Sym, have.Type, missing.Sym, missing.Type)
	} else if ptr != 0 {
		return fmt.Sprintf("%v does not implement %v (%v method has pointer receiver)", t, iface, missing.Sym)
	} else if have != nil {
		return fmt.Sprintf("%v does not implement %v (missing %v method)\n"+
			"\t\thave %v%S\n\t\twant %v%S", t, iface, missing.Sym, have.Sym, have.Type, missing.Sym, missing.Type)
	}
	return fmt.Sprintf("%v does not implement %v (missing %v method)", t, iface, missing.Sym)
}

// implements reports whether t implements the interface iface. t can be
// an interface, a type parameter, or a concrete type. If implements returns
// false, it stores a method of iface that is not implemented in *m. If the
// method name matches but the type is wrong, it additionally stores the type
// of the method (on t) in *samename.
func implements(t, iface *types.Type, m, samename **types.Field, ptr *int) bool {
	t0 := t
	if t == nil {
		return false
	}

	if t.IsInterface() {
		i := 0
		tms := t.AllMethods()
		for _, im := range iface.AllMethods() {
			for i < len(tms) && tms[i].Sym != im.Sym {
				i++
			}
			if i == len(tms) {
				*m = im
				*samename = nil
				*ptr = 0
				return false
			}
			tm := tms[i]
			if !types.Identical(tm.Type, im.Type) {
				*m = im
				*samename = tm
				*ptr = 0
				return false
			}
		}

		return true
	}

	t = types.ReceiverBaseType(t)
	var tms []*types.Field
	if t != nil {
		CalcMethods(t)
		tms = t.AllMethods()
	}
	i := 0
	for _, im := range iface.AllMethods() {
		for i < len(tms) && tms[i].Sym != im.Sym {
			i++
		}
		if i == len(tms) {
			*m = im
			*samename = ifacelookdot(im.Sym, t, true)
			*ptr = 0
			return false
		}
		tm := tms[i]
		if tm.Nointerface() || !types.Identical(tm.Type, im.Type) {
			*m = im
			*samename = tm
			*ptr = 0
			return false
		}

		// if pointer receiver in method,
		// the method does not exist for value types.
		if !types.IsMethodApplicable(t0, tm) {
			if false && base.Flag.LowerR != 0 {
				base.Errorf("interface pointer mismatch")
			}

			*m = im
			*samename = nil
			*ptr = 1
			return false
		}
	}

	return true
}

func isptrto(t *types.Type, et types.Kind) bool {
	if t == nil {
		return false
	}
	if !t.IsPtr() {
		return false
	}
	t = t.Elem()
	if t == nil {
		return false
	}
	if t.Kind() != et {
		return false
	}
	return true
}

// lookdot0 returns the number of fields or methods named s associated
// with Type t. If exactly one exists, it will be returned in *save
// (if save is not nil).
func lookdot0(s *types.Sym, t *types.Type, save **types.Field, ignorecase bool) int {
	u := t
	if u.IsPtr() {
		u = u.Elem()
	}

	c := 0
	if u.IsStruct() || u.IsInterface() {
		var fields []*types.Field
		if u.IsStruct() {
			fields = u.Fields()
		} else {
			fields = u.AllMethods()
		}
		for _, f := range fields {
			if f.Sym == s || (ignorecase && f.IsMethod() && strings.EqualFold(f.Sym.Name, s.Name)) {
				if save != nil {
					*save = f
				}
				c++
			}
		}
	}

	u = t
	if t.Sym() != nil && t.IsPtr() && !t.Elem().IsPtr() {
		// If t is a defined pointer type, then x.m is shorthand for (*x).m.
		u = t.Elem()
	}
	u = types.ReceiverBaseType(u)
	if u != nil {
		for _, f := range u.Methods() {
			if f.Embedded == 0 && (f.Sym == s || (ignorecase && strings.EqualFold(f.Sym.Name, s.Name))) {
				if save != nil {
					*save = f
				}
				c++
			}
		}
	}

	return c
}

var slist []symlink

// Code to help generate trampoline functions for methods on embedded
// types. These are approx the same as the corresponding AddImplicitDots
// routines except that they expect to be called with unique tasks and
// they return the actual methods.

type symlink struct {
	field *types.Field
}
```