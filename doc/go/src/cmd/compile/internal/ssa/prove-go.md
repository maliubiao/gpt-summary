Response: The user wants a summary of the Go code provided, specifically the `prove.go` file. The request includes several constraints:

1. **List Functionality:** Describe what the code does.
2. **Infer Go Feature:** If possible, determine what high-level Go feature this code implements.
3. **Code Example:** Provide a Go code example illustrating the inferred feature.
4. **Code Reasoning:** If the inference involves code analysis, explain the reasoning with assumed inputs and outputs.
5. **Command-line Arguments:** Detail any relevant command-line flags.
6. **Common Mistakes:** Point out potential user errors (if any).
7. **Part 1 Summary:** Provide an overall summary of the functionality described in this part of the file.

Let's break down the code and address each point:

**1. List Functionality:**

The code defines several key data structures and functions related to tracking and reasoning about the possible values and relationships between variables in a Go program's SSA (Static Single Assignment) representation. The main functionalities are:

* **Tracking Value Ranges (`limit`):**  It maintains upper and lower bounds for the possible values of variables, both signed and unsigned. This includes special handling for booleans and pointers.
* **Tracking Relationships (`relation`, `ordering`, `factsTable`):** It keeps track of known relationships (like `<`, `<=`, `==`, `!=`, `>`, `>=`) between pairs of variables in different domains (signed, unsigned, pointer, boolean).
* **Propagating Information:** It propagates the implications of known ranges and relationships. For example, if `v < w` and we know the range of `w`, it updates the possible range of `v`.
* **Detecting Unsatisfiability:**  It can detect contradictions in the tracked facts, indicating unreachable code.
* **Simplifying Code:** The `prove` function attempts to simplify the SSA by removing redundant branch conditions based on the established facts. This is done by checking if branch conditions or their negations lead to contradictions.
* **Handling Induction Variables:** The code identifies and reasons about loop induction variables to infer more facts about their values during loop execution.

**2. Infer Go Feature:**

Based on the functionality, this code is a core part of the **Go compiler's optimization pipeline**. Specifically, it implements a form of **value range analysis** and **constraint propagation**. This analysis helps the compiler understand the possible values of variables at different points in the program, which enables several optimizations, such as:

* **Dead code elimination:** Identifying and removing code that will never be executed (due to contradictory conditions).
* **Bounds check elimination:** Removing unnecessary array bounds checks when the compiler can prove that the index is always within the valid range.
* **Branch folding:** Simplifying conditional branches where the outcome can be determined statically.

**3. Code Example:**

Here's a Go code example where this kind of analysis would be beneficial for bounds check elimination:

```go
package main

import "fmt"

func main() {
	arr := [10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for i := 0; i < 10; i++ {
		fmt.Println(arr[i]) // The compiler can prove 'i' is always within bounds
	}
}
```

**4. Code Reasoning (with assumptions):**

* **Input:** The `prove` function receives an SSA-represented function (`*Func`). Let's consider the loop in the example above. The SSA would represent the loop counter `i` and the array access `arr[i]`.
* **Assumptions:** The `findIndVar` function (mentioned in the code) correctly identifies `i` as an induction variable with a range of 0 to 9.
* **Process:** The `prove` function, using the `factsTable`, would track the range of `i`. When it encounters the array access `arr[i]`, it would need to verify that `0 <= i < len(arr)`. The `factsTable` would contain the information that `0 <= i` and `i < 10` (because `len(arr)` is 10).
* **Output:** Because the `factsTable` can prove that the index `i` is always within the bounds of the array, the compiler can eliminate the runtime bounds check associated with `arr[i]`.

**5. Command-line Arguments:**

The provided code doesn't directly handle command-line arguments. However, the comment `// If v.Block.Func.pass.debug > 2` suggests that the debugging level of the compiler pass influences the output. This likely means that the `-gcflags` option used when compiling Go code could indirectly affect the behavior of this code by enabling debug output. For example:

```bash
go build -gcflags="-d=ssa/prove/debug=3" your_program.go
```

This would set the debug level for the `prove` pass to 3, potentially triggering more verbose logging within the `factsTable` updates.

**6. Common Mistakes:**

The code itself is part of the compiler, so user errors in writing Go code wouldn't directly break this logic. However, a common mistake that *this optimization aims to address* is writing code where bounds checks are redundant but the compiler isn't smart enough to eliminate them. The `prove` pass is intended to make the compiler smarter in such cases.

**7. Part 1 Summary:**

This part of the `prove.go` file focuses on setting up the infrastructure for value range analysis and constraint propagation within the Go compiler's SSA representation. It defines data structures to track the possible ranges of variables (`limit`), the relationships between variables (`relation`, `ordering`), and a table to store these facts (`factsTable`). It also includes functions for manipulating and updating this fact table, including intersecting limits, adding new limit constraints, and tracking orderings. The code lays the foundation for the `prove` function to reason about the program's state and perform optimizations based on the inferred facts.

这是 `go/src/cmd/compile/internal/ssa/prove.go` 文件的一部分，主要功能是实现 **静态分析** 和 **常量传播**，用于优化 Go 语言的编译过程。更具体地说，它旨在识别和消除冗余的条件分支（特别是由于数组越界检查产生的）。

以下是更详细的功能分解：

**核心功能:**

1. **跟踪变量的取值范围 (Value Range Tracking):**
   - 使用 `limit` 结构体来记录已知变量的上下界，包括有符号和无符号的范围。
   - 支持布尔值 (0/1) 和指针 (nil/non-nil) 的特殊范围表示。
   - 提供方法来计算两个范围的交集 (`intersect`)，以及更新范围的上下界 (`signedMin`, `signedMax`, `unsignedMin`, `unsignedMax` 等)。
   - 可以判断一个范围是否矛盾 (`unsat`)，即下界大于上界。
   - 提供安全加减法函数 (`safeAdd`, `safeSub` 等) 来处理溢出情况。

2. **跟踪变量之间的关系 (Relationship Tracking):**
   - 使用 `relation` 类型表示变量之间的关系，如小于、等于、大于等。
   - 使用 `ordering` 结构体记录已知两个变量之间的特定关系 (例如 `v < w`) 及其所在的域 (有符号、无符号、指针、布尔)。
   - 使用 `factsTable` 结构体来维护所有已知变量关系的集合。
   - `factsTable` 使用 `poset` (部分有序集) 来高效地存储和查询有符号和无符号变量之间的顺序关系。
   - `factsTable` 可以记录变量间的相等和不等关系，并检测关系中的矛盾 (`unsat` 标志)。

3. **条件分支的推断和消除 (Branch Pruning):**
   - `prove` 函数是核心，它遍历函数的控制流图 (CFG)。
   - 对于每个分支块 (`BlockIf`)，它尝试推断分支条件是否始终为真或假。
   - 它维护一个 `factsTable`，在遍历过程中累积已知的事实 (例如，到达某个块意味着之前某个比较的结果为真)。
   - 通过分别假设分支条件为真和假，然后检查 `factsTable` 是否出现矛盾，来判断分支是否可以被消除。如果假设分支条件为真导致矛盾，则意味着该分支永远不会被执行。

4. **处理循环归纳变量 (Induction Variable Handling):**
   - `prove` 函数会识别循环中的归纳变量 (例如循环计数器)。
   - 它会根据循环的初始值、步长和终止条件，向 `factsTable` 中添加关于归纳变量取值范围的约束。
   - 这有助于在循环内部进行更精确的静态分析。

5. **传播常量信息 (Constant Propagation):**
   - `flowLimit` 函数根据操作符和操作数的已知范围，推断出新的值的范围。
   - `addLocalFacts` 函数在每个基本块内部传播常量范围信息，并添加由特定操作引入的事实 (例如，`And` 操作的结果小于等于其操作数)。

**可以推理出的 Go 语言功能实现:**

这部分代码是 Go 编译器中 **SSA 优化 (Static Single Assignment Optimization)** 过程的关键组成部分。特别是，它支持以下优化：

* **边界检查消除 (Bounds Check Elimination):**  Go 语言为了安全，会在运行时检查数组、切片的访问是否越界。`prove` 尝试在编译时证明某些访问不会越界，从而消除运行时的检查，提高性能。

**Go 代码举例说明 (边界检查消除):**

```go
package main

import "fmt"

func main() {
	arr := [10]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	for i := 0; i < 10; i++ {
		fmt.Println(arr[i]) // 编译器可以通过 prove 证明 i 的范围是 [0, 9]，不会越界
	}
}
```

**假设的输入与输出 (针对上述代码):**

* **假设输入 (SSA 表示的一部分):**
    * 一个表示 `for` 循环的控制流图，包含一个循环头块和一个循环体块。
    * 循环头块包含一个比较操作 `i < 10` 和一个条件分支。
    * 循环体块包含一个数组访问操作 `arr[i]`。
* **`factsTable` 的状态变化:**
    1. 在进入循环头块时，`factsTable` 可能包含 `i >= 0` 的信息 (假设循环初始化为 0)。
    2. 由于分支条件 `i < 10` 为真，`factsTable` 更新为同时包含 `i >= 0` 和 `i < 10`。
    3. 在分析循环体块中的 `arr[i]` 时，`prove` 检查 `i` 的范围是否在 `arr` 的有效索引范围内 (0 到 9)。
    4. 由于 `factsTable` 中有 `0 <= i < 10` 的信息，`prove` 可以推断出数组访问不会越界。
* **输出 (优化后的 SSA 或机器码):**
    * 针对 `arr[i]` 的边界检查指令被移除。

**命令行参数的具体处理:**

代码中提到了 `v.Block.Func.pass.debug > 2`，这表明可以通过设置编译器的调试级别来影响 `prove` 过程的输出。具体的命令行参数通常是 `-gcflags`，例如：

```bash
go build -gcflags="-d=ssa/prove/debug=3" your_program.go
```

这个命令会以较高的调试级别编译 `your_program.go`，可能会在编译过程中输出更多关于 `prove` 过程的信息。具体的调试选项和级别可能需要查阅 Go 编译器的文档。

**使用者易犯错的点:**

由于这段代码是编译器的一部分，普通 Go 语言使用者不会直接与之交互，因此没有直接的使用者易犯错的点。但是，开发者可能会编写出一些编译器难以静态分析的代码，导致边界检查无法被消除，从而影响性能。例如，数组索引来自用户输入或者复杂的计算，使得编译器难以确定其范围。

**归纳一下它的功能 (第 1 部分):**

这部分代码为 Go 语言编译器中的 SSA 优化过程提供了核心的静态分析能力。它通过跟踪变量的取值范围和它们之间的关系，构建了一个用于推理程序行为的知识库 (`factsTable`)。这个知识库是后续优化步骤 (例如边界检查消除) 的基础。代码定义了关键的数据结构 (`limit`, `relation`, `ordering`, `factsTable`) 和相关的操作函数，用于维护和更新这个知识库。 `prove` 函数作为入口，利用这些信息来判断和消除冗余的条件分支。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/ssa/prove.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/internal/src"
	"fmt"
	"math"
	"math/bits"
)

type branch int

const (
	unknown branch = iota
	positive
	negative
	// The outedges from a jump table are jumpTable0,
	// jumpTable0+1, jumpTable0+2, etc. There could be an
	// arbitrary number so we can't list them all here.
	jumpTable0
)

func (b branch) String() string {
	switch b {
	case unknown:
		return "unk"
	case positive:
		return "pos"
	case negative:
		return "neg"
	default:
		return fmt.Sprintf("jmp%d", b-jumpTable0)
	}
}

// relation represents the set of possible relations between
// pairs of variables (v, w). Without a priori knowledge the
// mask is lt | eq | gt meaning v can be less than, equal to or
// greater than w. When the execution path branches on the condition
// `v op w` the set of relations is updated to exclude any
// relation not possible due to `v op w` being true (or false).
//
// E.g.
//
//	r := relation(...)
//
//	if v < w {
//	  newR := r & lt
//	}
//	if v >= w {
//	  newR := r & (eq|gt)
//	}
//	if v != w {
//	  newR := r & (lt|gt)
//	}
type relation uint

const (
	lt relation = 1 << iota
	eq
	gt
)

var relationStrings = [...]string{
	0: "none", lt: "<", eq: "==", lt | eq: "<=",
	gt: ">", gt | lt: "!=", gt | eq: ">=", gt | eq | lt: "any",
}

func (r relation) String() string {
	if r < relation(len(relationStrings)) {
		return relationStrings[r]
	}
	return fmt.Sprintf("relation(%d)", uint(r))
}

// domain represents the domain of a variable pair in which a set
// of relations is known. For example, relations learned for unsigned
// pairs cannot be transferred to signed pairs because the same bit
// representation can mean something else.
type domain uint

const (
	signed domain = 1 << iota
	unsigned
	pointer
	boolean
)

var domainStrings = [...]string{
	"signed", "unsigned", "pointer", "boolean",
}

func (d domain) String() string {
	s := ""
	for i, ds := range domainStrings {
		if d&(1<<uint(i)) != 0 {
			if len(s) != 0 {
				s += "|"
			}
			s += ds
			d &^= 1 << uint(i)
		}
	}
	if d != 0 {
		if len(s) != 0 {
			s += "|"
		}
		s += fmt.Sprintf("0x%x", uint(d))
	}
	return s
}

// a limit records known upper and lower bounds for a value.
//
// If we have min>max or umin>umax, then this limit is
// called "unsatisfiable". When we encounter such a limit, we
// know that any code for which that limit applies is unreachable.
// We don't particularly care how unsatisfiable limits propagate,
// including becoming satisfiable, because any optimization
// decisions based on those limits only apply to unreachable code.
type limit struct {
	min, max   int64  // min <= value <= max, signed
	umin, umax uint64 // umin <= value <= umax, unsigned
	// For booleans, we use 0==false, 1==true for both ranges
	// For pointers, we use 0,0,0,0 for nil and minInt64,maxInt64,1,maxUint64 for nonnil
}

func (l limit) String() string {
	return fmt.Sprintf("sm,SM,um,UM=%d,%d,%d,%d", l.min, l.max, l.umin, l.umax)
}

func (l limit) intersect(l2 limit) limit {
	if l.min < l2.min {
		l.min = l2.min
	}
	if l.umin < l2.umin {
		l.umin = l2.umin
	}
	if l.max > l2.max {
		l.max = l2.max
	}
	if l.umax > l2.umax {
		l.umax = l2.umax
	}
	return l
}

func (l limit) signedMin(m int64) limit {
	if l.min < m {
		l.min = m
	}
	return l
}
func (l limit) signedMax(m int64) limit {
	if l.max > m {
		l.max = m
	}
	return l
}
func (l limit) signedMinMax(min, max int64) limit {
	if l.min < min {
		l.min = min
	}
	if l.max > max {
		l.max = max
	}
	return l
}

func (l limit) unsignedMin(m uint64) limit {
	if l.umin < m {
		l.umin = m
	}
	return l
}
func (l limit) unsignedMax(m uint64) limit {
	if l.umax > m {
		l.umax = m
	}
	return l
}
func (l limit) unsignedMinMax(min, max uint64) limit {
	if l.umin < min {
		l.umin = min
	}
	if l.umax > max {
		l.umax = max
	}
	return l
}

func (l limit) nonzero() bool {
	return l.min > 0 || l.umin > 0 || l.max < 0
}
func (l limit) nonnegative() bool {
	return l.min >= 0
}
func (l limit) unsat() bool {
	return l.min > l.max || l.umin > l.umax
}

// If x and y can add without overflow or underflow
// (using b bits), safeAdd returns x+y, true.
// Otherwise, returns 0, false.
func safeAdd(x, y int64, b uint) (int64, bool) {
	s := x + y
	if x >= 0 && y >= 0 && s < 0 {
		return 0, false // 64-bit overflow
	}
	if x < 0 && y < 0 && s >= 0 {
		return 0, false // 64-bit underflow
	}
	if !fitsInBits(s, b) {
		return 0, false
	}
	return s, true
}

// same as safeAdd for unsigned arithmetic.
func safeAddU(x, y uint64, b uint) (uint64, bool) {
	s := x + y
	if s < x || s < y {
		return 0, false // 64-bit overflow
	}
	if !fitsInBitsU(s, b) {
		return 0, false
	}
	return s, true
}

// same as safeAdd but for subtraction.
func safeSub(x, y int64, b uint) (int64, bool) {
	if y == math.MinInt64 {
		if x == math.MaxInt64 {
			return 0, false // 64-bit overflow
		}
		x++
		y++
	}
	return safeAdd(x, -y, b)
}

// same as safeAddU but for subtraction.
func safeSubU(x, y uint64, b uint) (uint64, bool) {
	if x < y {
		return 0, false // 64-bit underflow
	}
	s := x - y
	if !fitsInBitsU(s, b) {
		return 0, false
	}
	return s, true
}

// fitsInBits reports whether x fits in b bits (signed).
func fitsInBits(x int64, b uint) bool {
	if b == 64 {
		return true
	}
	m := int64(-1) << (b - 1)
	M := -m - 1
	return x >= m && x <= M
}

// fitsInBitsU reports whether x fits in b bits (unsigned).
func fitsInBitsU(x uint64, b uint) bool {
	return x>>b == 0
}

// add returns the limit obtained by adding a value with limit l
// to a value with limit l2. The result must fit in b bits.
func (l limit) add(l2 limit, b uint) limit {
	r := noLimit
	min, minOk := safeAdd(l.min, l2.min, b)
	max, maxOk := safeAdd(l.max, l2.max, b)
	if minOk && maxOk {
		r.min = min
		r.max = max
	}
	umin, uminOk := safeAddU(l.umin, l2.umin, b)
	umax, umaxOk := safeAddU(l.umax, l2.umax, b)
	if uminOk && umaxOk {
		r.umin = umin
		r.umax = umax
	}
	return r
}

// same as add but for subtraction.
func (l limit) sub(l2 limit, b uint) limit {
	r := noLimit
	min, minOk := safeSub(l.min, l2.max, b)
	max, maxOk := safeSub(l.max, l2.min, b)
	if minOk && maxOk {
		r.min = min
		r.max = max
	}
	umin, uminOk := safeSubU(l.umin, l2.umax, b)
	umax, umaxOk := safeSubU(l.umax, l2.umin, b)
	if uminOk && umaxOk {
		r.umin = umin
		r.umax = umax
	}
	return r
}

// same as add but for multiplication.
func (l limit) mul(l2 limit, b uint) limit {
	r := noLimit
	umaxhi, umaxlo := bits.Mul64(l.umax, l2.umax)
	if umaxhi == 0 && fitsInBitsU(umaxlo, b) {
		r.umax = umaxlo
		r.umin = l.umin * l2.umin
		// Note: if the code containing this multiply is
		// unreachable, then we may have umin>umax, and this
		// multiply may overflow.  But that's ok for
		// unreachable code. If this code is reachable, we
		// know umin<=umax, so this multiply will not overflow
		// because the max multiply didn't.
	}
	// Signed is harder, so don't bother. The only useful
	// case is when we know both multiplicands are nonnegative,
	// but that case is handled above because we would have then
	// previously propagated signed info to the unsigned domain,
	// and will propagate it back after the multiply.
	return r
}

// Similar to add, but compute 1 << l if it fits without overflow in b bits.
func (l limit) exp2(b uint) limit {
	r := noLimit
	if l.umax < uint64(b) {
		r.umin = 1 << l.umin
		r.umax = 1 << l.umax
		// Same as above in mul, signed<->unsigned propagation
		// will handle the signed case for us.
	}
	return r
}

// Similar to add, but computes the complement of the limit for bitsize b.
func (l limit) com(b uint) limit {
	switch b {
	case 64:
		return limit{
			min:  ^l.max,
			max:  ^l.min,
			umin: ^l.umax,
			umax: ^l.umin,
		}
	case 32:
		return limit{
			min:  int64(^int32(l.max)),
			max:  int64(^int32(l.min)),
			umin: uint64(^uint32(l.umax)),
			umax: uint64(^uint32(l.umin)),
		}
	case 16:
		return limit{
			min:  int64(^int16(l.max)),
			max:  int64(^int16(l.min)),
			umin: uint64(^uint16(l.umax)),
			umax: uint64(^uint16(l.umin)),
		}
	case 8:
		return limit{
			min:  int64(^int8(l.max)),
			max:  int64(^int8(l.min)),
			umin: uint64(^uint8(l.umax)),
			umax: uint64(^uint8(l.umin)),
		}
	default:
		panic("unreachable")
	}
}

var noLimit = limit{math.MinInt64, math.MaxInt64, 0, math.MaxUint64}

// a limitFact is a limit known for a particular value.
type limitFact struct {
	vid   ID
	limit limit
}

// An ordering encodes facts like v < w.
type ordering struct {
	next *ordering // linked list of all known orderings for v.
	// Note: v is implicit here, determined by which linked list it is in.
	w *Value
	d domain
	r relation // one of ==,!=,<,<=,>,>=
	// if d is boolean or pointer, r can only be ==, !=
}

// factsTable keeps track of relations between pairs of values.
//
// The fact table logic is sound, but incomplete. Outside of a few
// special cases, it performs no deduction or arithmetic. While there
// are known decision procedures for this, the ad hoc approach taken
// by the facts table is effective for real code while remaining very
// efficient.
type factsTable struct {
	// unsat is true if facts contains a contradiction.
	//
	// Note that the factsTable logic is incomplete, so if unsat
	// is false, the assertions in factsTable could be satisfiable
	// *or* unsatisfiable.
	unsat      bool // true if facts contains a contradiction
	unsatDepth int  // number of unsat checkpoints

	// order* is a couple of partial order sets that record information
	// about relations between SSA values in the signed and unsigned
	// domain.
	orderS *poset
	orderU *poset

	// orderings contains a list of known orderings between values.
	// These lists are indexed by v.ID.
	// We do not record transitive orderings. Only explicitly learned
	// orderings are recorded. Transitive orderings can be obtained
	// by walking along the individual orderings.
	orderings map[ID]*ordering
	// stack of IDs which have had an entry added in orderings.
	// In addition, ID==0 are checkpoint markers.
	orderingsStack []ID
	orderingCache  *ordering // unused ordering records

	// known lower and upper constant bounds on individual values.
	limits       []limit     // indexed by value ID
	limitStack   []limitFact // previous entries
	recurseCheck []bool      // recursion detector for limit propagation

	// For each slice s, a map from s to a len(s)/cap(s) value (if any)
	// TODO: check if there are cases that matter where we have
	// more than one len(s) for a slice. We could keep a list if necessary.
	lens map[ID]*Value
	caps map[ID]*Value
}

// checkpointBound is an invalid value used for checkpointing
// and restoring factsTable.
var checkpointBound = limitFact{}

func newFactsTable(f *Func) *factsTable {
	ft := &factsTable{}
	ft.orderS = f.newPoset()
	ft.orderU = f.newPoset()
	ft.orderS.SetUnsigned(false)
	ft.orderU.SetUnsigned(true)
	ft.orderings = make(map[ID]*ordering)
	ft.limits = f.Cache.allocLimitSlice(f.NumValues())
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			ft.limits[v.ID] = initLimit(v)
		}
	}
	ft.limitStack = make([]limitFact, 4)
	ft.recurseCheck = f.Cache.allocBoolSlice(f.NumValues())
	return ft
}

// initLimitForNewValue initializes the limits for newly created values,
// possibly needing to expand the limits slice. Currently used by
// simplifyBlock when certain provably constant results are folded.
func (ft *factsTable) initLimitForNewValue(v *Value) {
	if int(v.ID) >= len(ft.limits) {
		f := v.Block.Func
		n := f.NumValues()
		if cap(ft.limits) >= n {
			ft.limits = ft.limits[:n]
		} else {
			old := ft.limits
			ft.limits = f.Cache.allocLimitSlice(n)
			copy(ft.limits, old)
			f.Cache.freeLimitSlice(old)
		}
	}
	ft.limits[v.ID] = initLimit(v)
}

// signedMin records the fact that we know v is at least
// min in the signed domain.
func (ft *factsTable) signedMin(v *Value, min int64) bool {
	return ft.newLimit(v, limit{min: min, max: math.MaxInt64, umin: 0, umax: math.MaxUint64})
}

// signedMax records the fact that we know v is at most
// max in the signed domain.
func (ft *factsTable) signedMax(v *Value, max int64) bool {
	return ft.newLimit(v, limit{min: math.MinInt64, max: max, umin: 0, umax: math.MaxUint64})
}
func (ft *factsTable) signedMinMax(v *Value, min, max int64) bool {
	return ft.newLimit(v, limit{min: min, max: max, umin: 0, umax: math.MaxUint64})
}

// setNonNegative records the fact that v is known to be non-negative.
func (ft *factsTable) setNonNegative(v *Value) bool {
	return ft.signedMin(v, 0)
}

// unsignedMin records the fact that we know v is at least
// min in the unsigned domain.
func (ft *factsTable) unsignedMin(v *Value, min uint64) bool {
	return ft.newLimit(v, limit{min: math.MinInt64, max: math.MaxInt64, umin: min, umax: math.MaxUint64})
}

// unsignedMax records the fact that we know v is at most
// max in the unsigned domain.
func (ft *factsTable) unsignedMax(v *Value, max uint64) bool {
	return ft.newLimit(v, limit{min: math.MinInt64, max: math.MaxInt64, umin: 0, umax: max})
}
func (ft *factsTable) unsignedMinMax(v *Value, min, max uint64) bool {
	return ft.newLimit(v, limit{min: math.MinInt64, max: math.MaxInt64, umin: min, umax: max})
}

func (ft *factsTable) booleanFalse(v *Value) bool {
	return ft.newLimit(v, limit{min: 0, max: 0, umin: 0, umax: 0})
}
func (ft *factsTable) booleanTrue(v *Value) bool {
	return ft.newLimit(v, limit{min: 1, max: 1, umin: 1, umax: 1})
}
func (ft *factsTable) pointerNil(v *Value) bool {
	return ft.newLimit(v, limit{min: 0, max: 0, umin: 0, umax: 0})
}
func (ft *factsTable) pointerNonNil(v *Value) bool {
	l := noLimit
	l.umin = 1
	return ft.newLimit(v, l)
}

// newLimit adds new limiting information for v.
// Returns true if the new limit added any new information.
func (ft *factsTable) newLimit(v *Value, newLim limit) bool {
	oldLim := ft.limits[v.ID]

	// Merge old and new information.
	lim := oldLim.intersect(newLim)

	// signed <-> unsigned propagation
	if lim.min >= 0 {
		lim = lim.unsignedMinMax(uint64(lim.min), uint64(lim.max))
	}
	if fitsInBitsU(lim.umax, uint(8*v.Type.Size()-1)) {
		lim = lim.signedMinMax(int64(lim.umin), int64(lim.umax))
	}

	if lim == oldLim {
		return false // nothing new to record
	}

	if lim.unsat() {
		ft.unsat = true
		return true
	}

	// Check for recursion. This normally happens because in unsatisfiable
	// cases we have a < b < a, and every update to a's limits returns
	// here again with the limit increased by 2.
	// Normally this is caught early by the orderS/orderU posets, but in
	// cases where the comparisons jump between signed and unsigned domains,
	// the posets will not notice.
	if ft.recurseCheck[v.ID] {
		// This should only happen for unsatisfiable cases. TODO: check
		return false
	}
	ft.recurseCheck[v.ID] = true
	defer func() {
		ft.recurseCheck[v.ID] = false
	}()

	// Record undo information.
	ft.limitStack = append(ft.limitStack, limitFact{v.ID, oldLim})
	// Record new information.
	ft.limits[v.ID] = lim
	if v.Block.Func.pass.debug > 2 {
		// TODO: pos is probably wrong. This is the position where v is defined,
		// not the position where we learned the fact about it (which was
		// probably some subsequent compare+branch).
		v.Block.Func.Warnl(v.Pos, "new limit %s %s unsat=%v", v, lim.String(), ft.unsat)
	}

	// Propagate this new constant range to other values
	// that we know are ordered with respect to this one.
	// Note overflow/underflow in the arithmetic below is ok,
	// it will just lead to imprecision (undetected unsatisfiability).
	for o := ft.orderings[v.ID]; o != nil; o = o.next {
		switch o.d {
		case signed:
			switch o.r {
			case eq: // v == w
				ft.signedMinMax(o.w, lim.min, lim.max)
			case lt | eq: // v <= w
				ft.signedMin(o.w, lim.min)
			case lt: // v < w
				ft.signedMin(o.w, lim.min+1)
			case gt | eq: // v >= w
				ft.signedMax(o.w, lim.max)
			case gt: // v > w
				ft.signedMax(o.w, lim.max-1)
			case lt | gt: // v != w
				if lim.min == lim.max { // v is a constant
					c := lim.min
					if ft.limits[o.w.ID].min == c {
						ft.signedMin(o.w, c+1)
					}
					if ft.limits[o.w.ID].max == c {
						ft.signedMax(o.w, c-1)
					}
				}
			}
		case unsigned:
			switch o.r {
			case eq: // v == w
				ft.unsignedMinMax(o.w, lim.umin, lim.umax)
			case lt | eq: // v <= w
				ft.unsignedMin(o.w, lim.umin)
			case lt: // v < w
				ft.unsignedMin(o.w, lim.umin+1)
			case gt | eq: // v >= w
				ft.unsignedMax(o.w, lim.umax)
			case gt: // v > w
				ft.unsignedMax(o.w, lim.umax-1)
			case lt | gt: // v != w
				if lim.umin == lim.umax { // v is a constant
					c := lim.umin
					if ft.limits[o.w.ID].umin == c {
						ft.unsignedMin(o.w, c+1)
					}
					if ft.limits[o.w.ID].umax == c {
						ft.unsignedMax(o.w, c-1)
					}
				}
			}
		case boolean:
			switch o.r {
			case eq:
				if lim.min == 0 && lim.max == 0 { // constant false
					ft.booleanFalse(o.w)
				}
				if lim.min == 1 && lim.max == 1 { // constant true
					ft.booleanTrue(o.w)
				}
			case lt | gt:
				if lim.min == 0 && lim.max == 0 { // constant false
					ft.booleanTrue(o.w)
				}
				if lim.min == 1 && lim.max == 1 { // constant true
					ft.booleanFalse(o.w)
				}
			}
		case pointer:
			switch o.r {
			case eq:
				if lim.umax == 0 { // nil
					ft.pointerNil(o.w)
				}
				if lim.umin > 0 { // non-nil
					ft.pointerNonNil(o.w)
				}
			case lt | gt:
				if lim.umax == 0 { // nil
					ft.pointerNonNil(o.w)
				}
				// note: not equal to non-nil doesn't tell us anything.
			}
		}
	}

	// If this is new known constant for a boolean value,
	// extract relation between its args. For example, if
	// We learn v is false, and v is defined as a<b, then we learn a>=b.
	if v.Type.IsBoolean() {
		// If we reach here, it is because we have a more restrictive
		// value for v than the default. The only two such values
		// are constant true or constant false.
		if lim.min != lim.max {
			v.Block.Func.Fatalf("boolean not constant %v", v)
		}
		isTrue := lim.min == 1
		if dr, ok := domainRelationTable[v.Op]; ok && v.Op != OpIsInBounds && v.Op != OpIsSliceInBounds {
			d := dr.d
			r := dr.r
			if d == signed && ft.isNonNegative(v.Args[0]) && ft.isNonNegative(v.Args[1]) {
				d |= unsigned
			}
			if !isTrue {
				r ^= (lt | gt | eq)
			}
			// TODO: v.Block is wrong?
			addRestrictions(v.Block, ft, d, v.Args[0], v.Args[1], r)
		}
		switch v.Op {
		case OpIsNonNil:
			if isTrue {
				ft.pointerNonNil(v.Args[0])
			} else {
				ft.pointerNil(v.Args[0])
			}
		case OpIsInBounds, OpIsSliceInBounds:
			// 0 <= a0 < a1 (or 0 <= a0 <= a1)
			r := lt
			if v.Op == OpIsSliceInBounds {
				r |= eq
			}
			if isTrue {
				// On the positive branch, we learn:
				//   signed: 0 <= a0 < a1 (or 0 <= a0 <= a1)
				//   unsigned:    a0 < a1 (or a0 <= a1)
				ft.setNonNegative(v.Args[0])
				ft.update(v.Block, v.Args[0], v.Args[1], signed, r)
				ft.update(v.Block, v.Args[0], v.Args[1], unsigned, r)
			} else {
				// On the negative branch, we learn (0 > a0 ||
				// a0 >= a1). In the unsigned domain, this is
				// simply a0 >= a1 (which is the reverse of the
				// positive branch, so nothing surprising).
				// But in the signed domain, we can't express the ||
				// condition, so check if a0 is non-negative instead,
				// to be able to learn something.
				r ^= (lt | gt | eq) // >= (index) or > (slice)
				if ft.isNonNegative(v.Args[0]) {
					ft.update(v.Block, v.Args[0], v.Args[1], signed, r)
				}
				ft.update(v.Block, v.Args[0], v.Args[1], unsigned, r)
				// TODO: v.Block is wrong here
			}
		}
	}

	return true
}

func (ft *factsTable) addOrdering(v, w *Value, d domain, r relation) {
	o := ft.orderingCache
	if o == nil {
		o = &ordering{}
	} else {
		ft.orderingCache = o.next
	}
	o.w = w
	o.d = d
	o.r = r
	o.next = ft.orderings[v.ID]
	ft.orderings[v.ID] = o
	ft.orderingsStack = append(ft.orderingsStack, v.ID)
}

// update updates the set of relations between v and w in domain d
// restricting it to r.
func (ft *factsTable) update(parent *Block, v, w *Value, d domain, r relation) {
	if parent.Func.pass.debug > 2 {
		parent.Func.Warnl(parent.Pos, "parent=%s, update %s %s %s", parent, v, w, r)
	}
	// No need to do anything else if we already found unsat.
	if ft.unsat {
		return
	}

	// Self-fact. It's wasteful to register it into the facts
	// table, so just note whether it's satisfiable
	if v == w {
		if r&eq == 0 {
			ft.unsat = true
		}
		return
	}

	if d == signed || d == unsigned {
		var ok bool
		order := ft.orderS
		if d == unsigned {
			order = ft.orderU
		}
		switch r {
		case lt:
			ok = order.SetOrder(v, w)
		case gt:
			ok = order.SetOrder(w, v)
		case lt | eq:
			ok = order.SetOrderOrEqual(v, w)
		case gt | eq:
			ok = order.SetOrderOrEqual(w, v)
		case eq:
			ok = order.SetEqual(v, w)
		case lt | gt:
			ok = order.SetNonEqual(v, w)
		default:
			panic("unknown relation")
		}
		ft.addOrdering(v, w, d, r)
		ft.addOrdering(w, v, d, reverseBits[r])

		if !ok {
			if parent.Func.pass.debug > 2 {
				parent.Func.Warnl(parent.Pos, "unsat %s %s %s", v, w, r)
			}
			ft.unsat = true
			return
		}
	}
	if d == boolean || d == pointer {
		for o := ft.orderings[v.ID]; o != nil; o = o.next {
			if o.d == d && o.w == w {
				// We already know a relationship between v and w.
				// Either it is a duplicate, or it is a contradiction,
				// as we only allow eq and lt|gt for these domains,
				if o.r != r {
					ft.unsat = true
				}
				return
			}
		}
		// TODO: this does not do transitive equality.
		// We could use a poset like above, but somewhat degenerate (==,!= only).
		ft.addOrdering(v, w, d, r)
		ft.addOrdering(w, v, d, r) // note: reverseBits unnecessary for eq and lt|gt.
	}

	// Extract new constant limits based on the comparison.
	vLimit := ft.limits[v.ID]
	wLimit := ft.limits[w.ID]
	// Note: all the +1/-1 below could overflow/underflow. Either will
	// still generate correct results, it will just lead to imprecision.
	// In fact if there is overflow/underflow, the corresponding
	// code is unreachable because the known range is outside the range
	// of the value's type.
	switch d {
	case signed:
		switch r {
		case eq: // v == w
			ft.signedMinMax(v, wLimit.min, wLimit.max)
			ft.signedMinMax(w, vLimit.min, vLimit.max)
		case lt: // v < w
			ft.signedMax(v, wLimit.max-1)
			ft.signedMin(w, vLimit.min+1)
		case lt | eq: // v <= w
			ft.signedMax(v, wLimit.max)
			ft.signedMin(w, vLimit.min)
		case gt: // v > w
			ft.signedMin(v, wLimit.min+1)
			ft.signedMax(w, vLimit.max-1)
		case gt | eq: // v >= w
			ft.signedMin(v, wLimit.min)
			ft.signedMax(w, vLimit.max)
		case lt | gt: // v != w
			if vLimit.min == vLimit.max { // v is a constant
				c := vLimit.min
				if wLimit.min == c {
					ft.signedMin(w, c+1)
				}
				if wLimit.max == c {
					ft.signedMax(w, c-1)
				}
			}
			if wLimit.min == wLimit.max { // w is a constant
				c := wLimit.min
				if vLimit.min == c {
					ft.signedMin(v, c+1)
				}
				if vLimit.max == c {
					ft.signedMax(v, c-1)
				}
			}
		}
	case unsigned:
		switch r {
		case eq: // v == w
			ft.unsignedMinMax(v, wLimit.umin, wLimit.umax)
			ft.unsignedMinMax(w, vLimit.umin, vLimit.umax)
		case lt: // v < w
			ft.unsignedMax(v, wLimit.umax-1)
			ft.unsignedMin(w, vLimit.umin+1)
		case lt | eq: // v <= w
			ft.unsignedMax(v, wLimit.umax)
			ft.unsignedMin(w, vLimit.umin)
		case gt: // v > w
			ft.unsignedMin(v, wLimit.umin+1)
			ft.unsignedMax(w, vLimit.umax-1)
		case gt | eq: // v >= w
			ft.unsignedMin(v, wLimit.umin)
			ft.unsignedMax(w, vLimit.umax)
		case lt | gt: // v != w
			if vLimit.umin == vLimit.umax { // v is a constant
				c := vLimit.umin
				if wLimit.umin == c {
					ft.unsignedMin(w, c+1)
				}
				if wLimit.umax == c {
					ft.unsignedMax(w, c-1)
				}
			}
			if wLimit.umin == wLimit.umax { // w is a constant
				c := wLimit.umin
				if vLimit.umin == c {
					ft.unsignedMin(v, c+1)
				}
				if vLimit.umax == c {
					ft.unsignedMax(v, c-1)
				}
			}
		}
	case boolean:
		switch r {
		case eq: // v == w
			if vLimit.min == 1 { // v is true
				ft.booleanTrue(w)
			}
			if vLimit.max == 0 { // v is false
				ft.booleanFalse(w)
			}
			if wLimit.min == 1 { // w is true
				ft.booleanTrue(v)
			}
			if wLimit.max == 0 { // w is false
				ft.booleanFalse(v)
			}
		case lt | gt: // v != w
			if vLimit.min == 1 { // v is true
				ft.booleanFalse(w)
			}
			if vLimit.max == 0 { // v is false
				ft.booleanTrue(w)
			}
			if wLimit.min == 1 { // w is true
				ft.booleanFalse(v)
			}
			if wLimit.max == 0 { // w is false
				ft.booleanTrue(v)
			}
		}
	case pointer:
		switch r {
		case eq: // v == w
			if vLimit.umax == 0 { // v is nil
				ft.pointerNil(w)
			}
			if vLimit.umin > 0 { // v is non-nil
				ft.pointerNonNil(w)
			}
			if wLimit.umax == 0 { // w is nil
				ft.pointerNil(v)
			}
			if wLimit.umin > 0 { // w is non-nil
				ft.pointerNonNil(v)
			}
		case lt | gt: // v != w
			if vLimit.umax == 0 { // v is nil
				ft.pointerNonNil(w)
			}
			if wLimit.umax == 0 { // w is nil
				ft.pointerNonNil(v)
			}
			// Note: the other direction doesn't work.
			// Being not equal to a non-nil pointer doesn't
			// make you (necessarily) a nil pointer.
		}
	}

	// Derived facts below here are only about numbers.
	if d != signed && d != unsigned {
		return
	}

	// Additional facts we know given the relationship between len and cap.
	//
	// TODO: Since prove now derives transitive relations, it
	// should be sufficient to learn that len(w) <= cap(w) at the
	// beginning of prove where we look for all len/cap ops.
	if v.Op == OpSliceLen && r&lt == 0 && ft.caps[v.Args[0].ID] != nil {
		// len(s) > w implies cap(s) > w
		// len(s) >= w implies cap(s) >= w
		// len(s) == w implies cap(s) >= w
		ft.update(parent, ft.caps[v.Args[0].ID], w, d, r|gt)
	}
	if w.Op == OpSliceLen && r&gt == 0 && ft.caps[w.Args[0].ID] != nil {
		// same, length on the RHS.
		ft.update(parent, v, ft.caps[w.Args[0].ID], d, r|lt)
	}
	if v.Op == OpSliceCap && r&gt == 0 && ft.lens[v.Args[0].ID] != nil {
		// cap(s) < w implies len(s) < w
		// cap(s) <= w implies len(s) <= w
		// cap(s) == w implies len(s) <= w
		ft.update(parent, ft.lens[v.Args[0].ID], w, d, r|lt)
	}
	if w.Op == OpSliceCap && r&lt == 0 && ft.lens[w.Args[0].ID] != nil {
		// same, capacity on the RHS.
		ft.update(parent, v, ft.lens[w.Args[0].ID], d, r|gt)
	}

	// Process fence-post implications.
	//
	// First, make the condition > or >=.
	if r == lt || r == lt|eq {
		v, w = w, v
		r = reverseBits[r]
	}
	switch r {
	case gt:
		if x, delta := isConstDelta(v); x != nil && delta == 1 {
			// x+1 > w  ⇒  x >= w
			//
			// This is useful for eliminating the
			// growslice branch of append.
			ft.update(parent, x, w, d, gt|eq)
		} else if x, delta := isConstDelta(w); x != nil && delta == -1 {
			// v > x-1  ⇒  v >= x
			ft.update(parent, v, x, d, gt|eq)
		}
	case gt | eq:
		if x, delta := isConstDelta(v); x != nil && delta == -1 {
			// x-1 >= w && x > min  ⇒  x > w
			//
			// Useful for i > 0; s[i-1].
			lim := ft.limits[x.ID]
			if (d == signed && lim.min > opMin[v.Op]) || (d == unsigned && lim.umin > 0) {
				ft.update(parent, x, w, d, gt)
			}
		} else if x, delta := isConstDelta(w); x != nil && delta == 1 {
			// v >= x+1 && x < max  ⇒  v > x
			lim := ft.limits[x.ID]
			if (d == signed && lim.max < opMax[w.Op]) || (d == unsigned && lim.umax < opUMax[w.Op]) {
				ft.update(parent, v, x, d, gt)
			}
		}
	}

	// Process: x+delta > w (with delta constant)
	// Only signed domain for now (useful for accesses to slices in loops).
	if r == gt || r == gt|eq {
		if x, delta := isConstDelta(v); x != nil && d == signed {
			if parent.Func.pass.debug > 1 {
				parent.Func.Warnl(parent.Pos, "x+d %s w; x:%v %v delta:%v w:%v d:%v", r, x, parent.String(), delta, w.AuxInt, d)
			}
			underflow := true
			if delta < 0 {
				l := ft.limits[x.ID]
				if (x.Type.Size() == 8 && l.min >= math.MinInt64-delta) ||
					(x.Type.Size() == 4 && l.min >= math.MinInt32-delta) {
					underflow = false
				}
			}
			if delta < 0 && !underflow {
				// If delta < 0 and x+delta cannot underflow then x > x+delta (that is, x > v)
				ft.update(parent, x, v, signed, gt)
			}
			if !w.isGenericIntConst() {
				// If we know that x+delta > w but w is not constant, we can derive:
				//    if delta < 0 and x+delta cannot underflow, then x > w
				// This is useful for loops with bounds "len(slice)-K" (delta = -K)
				if delta < 0 && !underflow {
					ft.update(parent, x, w, signed, r)
				}
			} else {
				// With w,delta constants, we want to derive: x+delta > w  ⇒  x > w-delta
				//
				// We compute (using integers of the correct size):
				//    min = w - delta
				//    max = MaxInt - delta
				//
				// And we prove that:
				//    if min<max: min < x AND x <= max
				//    if min>max: min < x OR  x <= max
				//
				// This is always correct, even in case of overflow.
				//
				// If the initial fact is x+delta >= w instead, the derived conditions are:
				//    if min<max: min <= x AND x <= max
				//    if min>max: min <= x OR  x <= max
				//
				// Notice the conditions for max are still <=, as they handle overflows.
				var min, max int64
				switch x.Type.Size() {
				case 8:
					min = w.AuxInt - delta
					max = int64(^uint64(0)>>1) - delta
				case 4:
					min = int64(int32(w.AuxInt) - int32(delta))
					max = int64(int32(^uint32(0)>>1) - int32(delta))
				case 2:
					min = int64(int16(w.AuxInt) - int16(delta))
					max = int64(int16(^uint16(0)>>1) - int16(delta))
				case 1:
					min = int64(int8(w.AuxInt) - int8(delta))
					max = int64(int8(^uint8(0)>>1) - int8(delta))
				default:
					panic("unimplemented")
				}

				if min < max {
					// Record that x > min and max >= x
					if r == gt {
						min++
					}
					ft.signedMinMax(x, min, max)
				} else {
					// We know that either x>min OR x<=max. factsTable cannot record OR conditions,
					// so let's see if we can already prove that one of them is false, in which case
					// the other must be true
					l := ft.limits[x.ID]
					if l.max <= min {
						if r&eq == 0 || l.max < min {
							// x>min (x>=min) is impossible, so it must be x<=max
							ft.signedMax(x, max)
						}
					} else if l.min > max {
						// x<=max is impossible, so it must be x>min
						if r == gt {
							min++
						}
						ft.signedMin(x, min)
					}
				}
			}
		}
	}

	// Look through value-preserving extensions.
	// If the domain is appropriate for the pre-extension Type,
	// repeat the update with the pre-extension Value.
	if isCleanExt(v) {
		switch {
		case d == signed && v.Args[0].Type.IsSigned():
			fallthrough
		case d == unsigned && !v.Args[0].Type.IsSigned():
			ft.update(parent, v.Args[0], w, d, r)
		}
	}
	if isCleanExt(w) {
		switch {
		case d == signed && w.Args[0].Type.IsSigned():
			fallthrough
		case d == unsigned && !w.Args[0].Type.IsSigned():
			ft.update(parent, v, w.Args[0], d, r)
		}
	}
}

var opMin = map[Op]int64{
	OpAdd64: math.MinInt64, OpSub64: math.MinInt64,
	OpAdd32: math.MinInt32, OpSub32: math.MinInt32,
}

var opMax = map[Op]int64{
	OpAdd64: math.MaxInt64, OpSub64: math.MaxInt64,
	OpAdd32: math.MaxInt32, OpSub32: math.MaxInt32,
}

var opUMax = map[Op]uint64{
	OpAdd64: math.MaxUint64, OpSub64: math.MaxUint64,
	OpAdd32: math.MaxUint32, OpSub32: math.MaxUint32,
}

// isNonNegative reports whether v is known to be non-negative.
func (ft *factsTable) isNonNegative(v *Value) bool {
	return ft.limits[v.ID].min >= 0
}

// checkpoint saves the current state of known relations.
// Called when descending on a branch.
func (ft *factsTable) checkpoint() {
	if ft.unsat {
		ft.unsatDepth++
	}
	ft.limitStack = append(ft.limitStack, checkpointBound)
	ft.orderS.Checkpoint()
	ft.orderU.Checkpoint()
	ft.orderingsStack = append(ft.orderingsStack, 0)
}

// restore restores known relation to the state just
// before the previous checkpoint.
// Called when backing up on a branch.
func (ft *factsTable) restore() {
	if ft.unsatDepth > 0 {
		ft.unsatDepth--
	} else {
		ft.unsat = false
	}
	for {
		old := ft.limitStack[len(ft.limitStack)-1]
		ft.limitStack = ft.limitStack[:len(ft.limitStack)-1]
		if old.vid == 0 { // checkpointBound
			break
		}
		ft.limits[old.vid] = old.limit
	}
	ft.orderS.Undo()
	ft.orderU.Undo()
	for {
		id := ft.orderingsStack[len(ft.orderingsStack)-1]
		ft.orderingsStack = ft.orderingsStack[:len(ft.orderingsStack)-1]
		if id == 0 { // checkpoint marker
			break
		}
		o := ft.orderings[id]
		ft.orderings[id] = o.next
		o.next = ft.orderingCache
		ft.orderingCache = o
	}
}

var (
	reverseBits = [...]relation{0, 4, 2, 6, 1, 5, 3, 7}

	// maps what we learn when the positive branch is taken.
	// For example:
	//      OpLess8:   {signed, lt},
	//	v1 = (OpLess8 v2 v3).
	// If we learn that v1 is true, then we can deduce that v2<v3
	// in the signed domain.
	domainRelationTable = map[Op]struct {
		d domain
		r relation
	}{
		OpEq8:   {signed | unsigned, eq},
		OpEq16:  {signed | unsigned, eq},
		OpEq32:  {signed | unsigned, eq},
		OpEq64:  {signed | unsigned, eq},
		OpEqPtr: {pointer, eq},
		OpEqB:   {boolean, eq},

		OpNeq8:   {signed | unsigned, lt | gt},
		OpNeq16:  {signed | unsigned, lt | gt},
		OpNeq32:  {signed | unsigned, lt | gt},
		OpNeq64:  {signed | unsigned, lt | gt},
		OpNeqPtr: {pointer, lt | gt},
		OpNeqB:   {boolean, lt | gt},

		OpLess8:   {signed, lt},
		OpLess8U:  {unsigned, lt},
		OpLess16:  {signed, lt},
		OpLess16U: {unsigned, lt},
		OpLess32:  {signed, lt},
		OpLess32U: {unsigned, lt},
		OpLess64:  {signed, lt},
		OpLess64U: {unsigned, lt},

		OpLeq8:   {signed, lt | eq},
		OpLeq8U:  {unsigned, lt | eq},
		OpLeq16:  {signed, lt | eq},
		OpLeq16U: {unsigned, lt | eq},
		OpLeq32:  {signed, lt | eq},
		OpLeq32U: {unsigned, lt | eq},
		OpLeq64:  {signed, lt | eq},
		OpLeq64U: {unsigned, lt | eq},
	}
)

// cleanup returns the posets to the free list
func (ft *factsTable) cleanup(f *Func) {
	for _, po := range []*poset{ft.orderS, ft.orderU} {
		// Make sure it's empty as it should be. A non-empty poset
		// might cause errors and miscompilations if reused.
		if checkEnabled {
			if err := po.CheckEmpty(); err != nil {
				f.Fatalf("poset not empty after function %s: %v", f.Name, err)
			}
		}
		f.retPoset(po)
	}
	f.Cache.freeLimitSlice(ft.limits)
	f.Cache.freeBoolSlice(ft.recurseCheck)
}

// prove removes redundant BlockIf branches that can be inferred
// from previous dominating comparisons.
//
// By far, the most common redundant pair are generated by bounds checking.
// For example for the code:
//
//	a[i] = 4
//	foo(a[i])
//
// The compiler will generate the following code:
//
//	if i >= len(a) {
//	    panic("not in bounds")
//	}
//	a[i] = 4
//	if i >= len(a) {
//	    panic("not in bounds")
//	}
//	foo(a[i])
//
// The second comparison i >= len(a) is clearly redundant because if the
// else branch of the first comparison is executed, we already know that i < len(a).
// The code for the second panic can be removed.
//
// prove works by finding contradictions and trimming branches whose
// conditions are unsatisfiable given the branches leading up to them.
// It tracks a "fact table" of branch conditions. For each branching
// block, it asserts the branch conditions that uniquely dominate that
// block, and then separately asserts the block's branch condition and
// its negation. If either leads to a contradiction, it can trim that
// successor.
func prove(f *Func) {
	// Find induction variables. Currently, findIndVars
	// is limited to one induction variable per block.
	var indVars map[*Block]indVar
	for _, v := range findIndVar(f) {
		ind := v.ind
		if len(ind.Args) != 2 {
			// the rewrite code assumes there is only ever two parents to loops
			panic("unexpected induction with too many parents")
		}

		nxt := v.nxt
		if !(ind.Uses == 2 && // 2 used by comparison and next
			nxt.Uses == 1) { // 1 used by induction
			// ind or nxt is used inside the loop, add it for the facts table
			if indVars == nil {
				indVars = make(map[*Block]indVar)
			}
			indVars[v.entry] = v
			continue
		} else {
			// Since this induction variable is not used for anything but counting the iterations,
			// no point in putting it into the facts table.
		}

		// try to rewrite to a downward counting loop checking against start if the
		// loop body does not depends on ind or nxt and end is known before the loop.
		// This reduce pressure on the register allocator because this do not need
		// to use end on each iteration anymore. We compare against the start constant instead.
		// That means this code:
		//
		//	loop:
		//		ind = (Phi (Const [x]) nxt),
		//		if ind < end
		//		then goto enter_loop
		//		else goto exit_loop
		//
		//	enter_loop:
		//		do something without using ind nor nxt
		//		nxt = inc + ind
		//		goto loop
		//
		//	exit_loop:
		//
		// is rewritten to:
		//
		//	loop:
		//		ind = (Phi end nxt)
		//		if (Const [x]) < ind
		//		then goto enter_loop
		//		else goto exit_loop
		//
		//	enter_loop:
		//		do something without using ind nor nxt
		//		nxt = ind - inc
		//		goto loop
		//
		//	exit_loop:
		//
		// this is better because it only require to keep ind then nxt alive while looping,
		// while the original form keeps ind then nxt and end alive
		start, end := v.min, v.max
		if v.flags&indVarCountDown != 0 {
			start, end = end, start
		}

		if !(start.Op == OpConst8 || start.Op == OpConst16 || start.Op == OpConst32 || start.Op == OpConst64) {
			// if start is not a constant we would be winning nothing from inverting the loop
			continue
		}
		if end.Op == OpConst8 || end.Op == OpConst16 || end.Op == OpConst32 || end.Op == OpConst64 {
			// TODO: if both start and end are constants we should rewrite such that the comparison
			// is against zero and nxt is ++ or -- operation
			// That means:
			//	for i := 2; i < 11; i += 2 {
			// should be rewritten to:
			//	for i := 5; 0 < i; i-- {
			continue
		}

		if end.Block == ind.Block {
			// we can't rewrite loops where the condition depends on the loop body
			// this simple check is forced to work because if this is true a Phi in ind.Block must exists
			continue
		}

		check := ind.Block.Controls[0]
		// invert the check
		check.Args[0], check.Args[1] = check.Args[1], check.Args[0]

		// swap start and end in the loop
		for i, v := range check.Args {
			if v != end {
				continue
			}

			check.SetArg(i, start)
			goto replacedEnd
		}
		panic(fmt.Sprintf("unreachable, ind: %v, start: %v, end: %v", ind, start, end))
	replacedEnd:

		for i, v := range ind.Args {
			if v != start {
				continue
			}

			ind.SetArg(i, end)
			goto replacedStart
		}
		panic(fmt.Sprintf("unreachable, ind: %v, start: %v, end: %v", ind, start, end))
	replacedStart:

		if nxt.Args[0] != ind {
			// unlike additions subtractions are not commutative so be sure we get it right
			nxt.Args[0], nxt.Args[1] = nxt.Args[1], nxt.Args[0]
		}

		switch nxt.Op {
		case OpAdd8:
			nxt.Op = OpSub8
		case OpAdd16:
			nxt.Op = OpSub16
		case OpAdd32:
			nxt.Op = OpSub32
		case OpAdd64:
			nxt.Op = OpSub64
		case OpSub8:
			nxt.Op = OpAdd8
		case OpSub16:
			nxt.Op = OpAdd16
		case OpSub32:
			nxt.Op = OpAdd32
		case OpSub64:
			nxt.Op = OpAdd64
		default:
			panic("unreachable")
		}

		if f.pass.debug > 0 {
			f.Warnl(ind.Pos, "Inverted loop iteration")
		}
	}

	ft := newFactsTable(f)
	ft.checkpoint()

	// Find length and capacity ops.
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Uses == 0 {
				// We don't care about dead values.
				// (There can be some that are CSEd but not removed yet.)
				continue
			}
			switch v.Op {
			case OpSliceLen:
				if ft.lens == nil {
					ft.lens = map[ID]*Value{}
				}
				// Set all len Values for the same slice as equal in the poset.
				// The poset handles transitive relations, so Values related to
				// any OpSliceLen for this slice will be correctly related to others.
				if l, ok := ft.lens[v.Args[0].ID]; ok {
					ft.update(b, v, l, signed, eq)
				} else {
					ft.lens[v.Args[0].ID] = v
				}
			case OpSliceCap:
				if ft.caps == nil {
					ft.caps = map[ID]*Value{}
				}
				// Same as case OpSliceLen above, but for slice cap.
				if c, ok := ft.caps[v.Args[0].ID]; ok {
					ft.update(b, v, c, signed, eq)
				} else {
					ft.caps[v.Args[0].ID] = v
				}
			}
		}
	}

	// current node state
	type walkState int
	const (
		descend walkState = iota
		simplify
	)
	// work maintains the DFS stack.
	type bp struct {
		block *Block    // current handled block
		state walkState // what's to do
	}
	work := make([]bp, 0, 256)
	work = append(work, bp{
		block: f.Entry,
		state: descend,
	})

	idom := f.Idom()
	sdom := f.Sdom()

	// DFS on the dominator tree.
	//
	// For efficiency, we consider only the dominator tree rather
	// than the entire flow graph. On the way down, we consider
	// incoming branches and accumulate conditions that uniquely
	// dominate the current block. If we discover a contradiction,
	// we can eliminate the entire block and all of its children.
	// On the way back up, we consider outgoing branches that
	// haven't already been considered. This way we consider each
	// branch condition only once.
	for len(work) > 0 {
		node := work[len(work)-1]
		work = work[:len(work)-1]
		parent := idom[node.block.ID]
		branch := getBranch(sdom, parent, node.block)

		switch node.state {
		case descend:
			ft.checkpoint()

			// Entering the block, add facts about the induction variable
			// that is bound to this block.
			if iv, ok := indVars[node.block]; ok {
				addIndVarRestrictions(ft, parent, iv)
			}

			// Add results of reaching this block via a branch from
			// its immediate dominator (if any).
			if branch != unknown {
				addBranchRestrictions(ft, parent, branch)
			}

			if ft.unsat {
				// node.block is unreachable.
				// Remove it and don't visit
				// its children.
				removeBranch(parent, branch)
				ft.restore()
				break
			}
			// Otherwise, we can now commit to
			// taking this branch. We'll restore
			// ft when we unwind.

			// Add facts about the values in the current block.
			addLocalFacts(ft, node.block)

			work = append(work, bp{
				block: node.block,
				state: simplify,
			})
			for s := sdom.Child(node.block); s != nil; s = sdom.Sibling(s) {
				work = append(work, bp{
					block: s,
					state: descend,
				})
			}

		case simplify:
			simplifyBlock(sdom, ft, node.block)
			ft.restore()
		}
	}

	ft.restore()

	ft.cleanup(f)
}

// initLimit sets initial constant limit for v.  This limit is based
// only on the operation itself, not any of its input arguments. This
// method is only used in two places, once when the prove pass startup
// and the other when a new ssa value is created, both for init. (unlike
// flowLimit, below, which computes additional constraints based on
// ranges of opcode arguments).
func initLimit(v *Value) limit {
	if v.Type.IsBoolean() {
		switch v.Op {
		case OpConstBool:
			b := v.AuxInt
			return limit{min: b, max: b, umin: uint64(b), umax: uint64(b)}
		default:
			return limit{min: 0, max: 1, umin: 0, umax: 1}
		}
	}
	if v.Type.IsPtrShaped() { // These are the types that EqPtr/NeqPtr operate on, except uintptr.
		switch v.Op {
		case OpConstNil:
			return limit{min: 0, max: 0, umin: 0, umax: 0}
		case OpAddr, OpLocalAddr: // TODO: others?
			l := noLimit
			l.umin = 1
			return l
		default:
			return noLimit
		}
	}
	if !v.Type.IsInteger() {
		return noLimit
	}

	// Default limits based on type.
	var lim limit
	switch v.Type.Size() {
	case 8:
		lim = limit{min: math.MinInt64, max: math.MaxInt64, umin: 0, umax: math.MaxUint64}
	case 4:
		lim = limit{min: math.MinInt32, max: math.MaxInt32, umin: 0, umax: math.MaxUint32}
	case 2:
		lim = limit{min: math.MinInt16, max: math.MaxInt16, umin: 0, umax: math.MaxUint16}
	case 1:
		lim = limit{min: math.MinInt8, max: math.MaxInt8, umin: 0, umax: math.MaxUint8}
	default:
		panic("bad")
	}

	// Tighter limits on some opcodes.
	switch v.Op {
	// constants
	case OpConst64:
		lim = limit{min: v.AuxInt, max: v.AuxInt, umin: uint64(v.AuxInt), umax: uint64(v.AuxInt)}
	case OpConst32:
		lim = limit{min: v.AuxInt, max: v.AuxInt, umin: uint64(uint32(v.AuxInt)), umax: uint64(uint32(v.AuxInt))}
	case OpConst16:
		lim = limit{min: v.AuxInt, max: v.AuxInt, umin: uint64(uint16(v.AuxInt)), umax: uint64(uint16(v.AuxInt))}
	case OpConst8:
		lim = limit{min: v.AuxInt, max: v.AuxInt, umin: uint64(uint8(v.AuxInt)), umax: uint64(uint8(v.AuxInt))}

	// extensions
	case OpZeroExt8to64, OpZeroExt8to32, OpZeroExt8to16:
		lim = lim.signedMinMax(0, 1<<8-1)
		lim = lim.unsignedMax(1<<8 - 1)
	case OpZeroExt16to64, OpZeroExt16to32:
		lim = lim.signedMinMax(0, 1<<16-1)
		lim = lim.unsignedMax(1<<16 - 1)
	case OpZeroExt32to64:
		lim = lim.signedMinMax(0, 1<<32-1)
		lim = lim.unsignedMax(1<<32 - 1)
	case OpSignExt8to64, OpSignExt8to32, OpSignExt8to16:
		lim = lim.signedMinMax(math.MinInt8, math.MaxInt8)
	case OpSignExt16to64, OpSignExt16to32:
		lim = lim.signedMinMax(math.MinInt16, math.MaxInt16)
	case OpSignExt32to64:
		lim = lim.signedMinMax(math.MinInt32, math.MaxInt32)

	// math/bits intrinsics
	case OpCtz64, OpBitLen64:
		lim = lim.unsignedMax(64)
	case OpCtz32, OpBitLen32:
		lim = lim.unsignedMax(32)
	case OpCtz16, OpBitLen16:
		lim = lim.unsignedMax(16)
	case OpCtz8, OpBitLen8:
		lim = lim.unsignedMax(8)

	// length operations
	case OpStringLen, OpSliceLen, OpSliceCap:
		lim = lim.signedMin(0)
	}

	// signed <-> unsigned propagation
	if lim.min >= 0 {
		lim = lim.unsignedMinMax(uint64(lim.min), uint64(lim.max))
	}
	if fitsInBitsU(lim.umax, uint(8*v.Type.Size()-1)) {
		lim = lim.signedMinMax(int64(lim.umin), int64(lim.umax))
	}

	return lim
}

// flowLimit updates the known limits of v in ft. Returns true if anything changed.
// flowLimit can use the ranges of input arguments.
//
// Note: this calculation only happens at the point the value is defined. We do not reevaluate
// it later. So for example:
//
//	v := x + y
//	if 0 <= x && x < 5 && 0 <= y && y < 5 { ... use v ... }
//
// we don't discover that the range of v is bounded in the conditioned
// block. We could recompute the range of v once we enter the block so
// we know that it is 0 <= v <= 8, but we don't have a mechanism to do
// that right now.
func (ft *factsTable) flowLimit(v *Value) bool {
	if !v.Type.IsInteger() {
		// TODO: boolean?
		return false
	}

	// Additional limits based on opcode and argument.
	// No need to repeat things here already done in initLimit.
	switch v.Op {

	// extensions
	case OpZeroExt8to64, OpZeroExt8to32, OpZeroExt8to16, OpZeroExt16to64, OpZeroExt16to32, OpZeroExt32to64:
		a := ft.limits[v.Args[0].ID]
		return ft.unsignedMinMax(v, a.umin, a.umax)
	case OpSignExt8to64, OpSignExt8to32, OpSignExt8to16, OpSignExt16to64, OpSignExt16to32, OpSignExt32to64:
		a := ft.limits[v.Args[0].ID]
		return ft.signedMinMax(v, a.min, a.max)
	case OpTrunc64to8, OpTrunc64to16, OpTrunc64to32, OpTrunc32to8, OpTrunc32to16, OpTrunc16to8:
		a := ft.limits[v.Args[0].ID]
		if a.umax <= 1<<(uint64(v.Type.Size())*8)-1 {
			return ft.unsignedMinMax(v, a.umin, a.umax)
		}

	// math/bits
	case OpCtz64:
		a := ft.limits[v.Args[0].ID]
		if a.nonzero() {
			return ft.unsignedMax(v, uint64(bits.Len64(a.umax)-1))
		}
	case OpCtz32:
		a := ft.limits[v.Args[0].ID]
		if a.nonzero() {
			return ft.unsignedMax(v, uint64(bits.Len32(uint32(a.umax))-1))
		}
	case OpCtz16:
		a := ft.limits[v.Args[0].ID]
		if a.nonzero() {
			return ft.unsignedMax(v, uint64(bits.Len16(uint16(a.umax))-1))
		}
	case OpCtz8:
		a := ft.limits[v.Args[0].ID]
		if a.nonzero() {
			return ft.unsignedMax(v, uint64(bits.Len8(uint8(a.umax))-1))
		}

	case OpBitLen64:
		a := ft.limits[v.Args[0].ID]
		return ft.unsignedMinMax(v,
			uint64(bits.Len64(a.umin)),
			uint64(bits.Len64(a.umax)))
	case OpBitLen32:
		a := ft.limits[v.Args[0].ID]
		return ft.unsignedMinMax(v,
			uint64(bits.Len32(uint32(a.umin))),
			uint64(bits.Len32(uint32(a.umax))))
	case OpBitLen16:
		a := ft.limits[v.Args[0].ID]
		return ft.unsignedMinMax(v,
			uint64(bits.Len16(uint16(a.umin))),
			uint64(bits.Len16(uint16(a.umax))))
	case OpBitLen8:
		a := ft.limits[v.Args[0].ID]
		return ft.unsignedMinMax(v,
			uint64(bits.Len8(uint8(a.umin))),
			uint64(bits.Len8(uint8(a.umax))))

	// Masks.

	// TODO: if y.umax and y.umin share a leading bit pattern, y also has that leading bit pattern.
	// we could compare the patterns of always set bits in a and b and learn more about minimum and maximum.
	// But I doubt this help any real world code.
	case OpAnd64, OpAnd32, OpAnd16, OpAnd8:
		// AND can only make the value smaller.
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.unsignedMax(v, min(a.umax, b.umax))
	case OpOr64, OpOr32, OpOr16, OpOr8:
		// OR can only make the value bigger and can't flip bits proved to be zero in both inputs.
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.unsignedMinMax(v,
			max(a.umin, b.umin),
			1<<bits.Len64(a.umax|b.umax)-1)
	case OpXor64, OpXor32, OpXor16, OpXor8:
		// XOR can't flip bits that are proved to be zero in both inputs.
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.unsignedMax(v, 1<<bits.Len64(a.umax|b.umax)-1)
	case OpCom64, OpCom32, OpCom16, OpCom8:
		a := ft.limits[v.Args[0].ID]
		return ft.newLimit(v, a.com(uint(v.Type.Size())*8))

	// Arithmetic.
	case OpAdd64:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.add(b, 64))
	case OpAdd32:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.add(b, 32))
	case OpAdd16:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.add(b, 16))
	case OpAdd8:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.add(b, 8))
	case OpSub64:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.sub(b, 64))
	case OpSub32:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.sub(b, 32))
	case OpSub16:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.sub(b, 16))
	case OpSub8:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.sub(b, 8))
	case OpNeg64, OpNeg32, OpNeg16, OpNeg8:
		a := ft.limits[v.Args[0].ID]
		bitsize := uint(v.Type.Size()) * 8
		return ft.newLimit(v, a.com(bitsize).add(limit{min: 1, max: 1, umin: 1, umax: 1}, bitsize))
	case OpMul64:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.mul(b, 64))
	case OpMul32:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.mul(b, 32))
	case OpMul16:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.mul(b, 16))
	case OpMul8:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.mul(b, 8))
	case OpLsh64x64, OpLsh64x32, OpLsh64x16, OpLsh64x8:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.mul(b.exp2(64), 64))
	case OpLsh32x64, OpLsh32x32, OpLsh32x16, OpLsh32x8:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.mul(b.exp2(32), 32))
	case OpLsh16x64, OpLsh16x32, OpLsh16x16, OpLsh16x8:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.mul(b.exp2(16), 16))
	case OpLsh8x64, OpLsh8x32, OpLsh8x16, OpLsh8x8:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		return ft.newLimit(v, a.mul(b.exp2(8), 8))
	case OpMod64, OpMod32, OpMod16, OpMod8:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		if !(a.nonnegative() && b.nonnegative()) {
			// TODO: we could handle signed limits but I didn't bother.
			break
		}
		fallthrough
	case OpMod64u, OpMod32u, OpMod16u, OpMod8u:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		// Underflow in the arithmetic below is ok, it gives to MaxUint64 which does nothing to the limit.
		return ft.unsignedMax(v, min(a.umax, b.umax-1))
	case OpDiv64, OpDiv32, OpDiv16, OpDiv8:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		if !(a.nonnegative() && b.nonnegative()) {
			// TODO: we could handle signed limits but I didn't bother.
			break
		}
		fallthrough
	case OpDiv64u, OpDiv32u, OpDiv16u, OpDiv8u:
		a := ft.limits[v.Args[0].ID]
		b := ft.limits[v.Args[1].ID]
		lim := noLimit
		if b.umax > 0 {
			lim = lim.unsignedMin(a.umin / b.umax)
		}
		if b.umin > 0 {
			lim = lim.unsignedMax(a.umax / b.umin)
		}
		return ft.newLimit(v, lim)

	case OpPhi:
		// Compute the union of all the input phis.
		// Often this will convey no information, because the block
		// is not dominated by its predecessors and hence the
		// phi arguments might not have been processed yet. But if
		// the values are declared earlier, it may help. e.g., for
		//    v = phi(c3, c5)
		// where c3 = OpConst [3] and c5 = OpConst [5] are
		// defined in the entry block, we can derive [3,5]
		// as the limit for v.
		l := ft.limits[v.Args[0].ID]
		for _, a := range v.Args[1:] {
			l2 := ft.limits[a.ID]
			l.min = min(l.min, l2.min)
			l.max = max(l.max, l2.max)
			l.umin = min(l.umin, l2.umin)
			l.umax = max(l.umax, l2.umax)
		}
		return ft.newLimit(v, l)
	}
	return false
}

// getBranch returns the range restrictions added by p
// when reaching b. p is the immediate dominator of b.
func getBranch(sdom SparseTree, p *Block, b *Block) branch {
	if p == nil {
		return unknown
	}
	switch p.Kind {
	case BlockIf:
		// If p and p.Succs[0] are dominators it means that every path
		// from entry to b passes through p and p.Succs[0]. We care that
		// no path from entry to b passes through p.Succs[1]. If p.Succs[0]
		// has one predecessor then (apart from the degenerate case),
		// there is no path from entry that can reach b through p.Succs[1].
		// TODO: how about p->yes->b->yes, i.e. a loop in yes.
		if sdom.IsAncestorEq(p.Succs[0].b, b) && len(p.Succs[0].b.Preds) == 1 {
			return positive
		}
		if sdom.IsAncestorEq(p.Succs[1].b, b) && len(p.Succs[1].b.Preds) == 1 {
			return negative
		}
	case BlockJumpTable:
		// TODO: this loop can lead to quadratic behavior, as
		// getBranch can be called len(p.Succs) times.
		for i, e := range p.Succs {
			if sdom.IsAncestorEq(e.b, b) && len(e.b.Preds) == 1 {
				return jumpTable0 + branch(i)
			}
		}
	}
	return unknown
}

// addIndVarRestrictions updates the factsTables ft with the facts
// learned from the induction variable indVar which drives the loop
// starting in Block b.
func addIndVarRestrictions(ft *factsTable, b *Block, iv indVar) {
	d := signed
	if ft.isNonNegative(iv.min) && ft.isNonNegative(iv.max) {
		d |= unsigned
	}

	if iv.flags&indVarMinExc == 0 {
		addRestrictions(b, ft, d, iv.min, iv.ind, lt|eq)
	} else {
		addRestrictions(b, ft, d, iv.min, iv.ind, lt)
	}

	if iv.flags&indVarMaxInc == 0 {
		addRestrictions(b, ft, d, iv.ind, iv.max, lt)
	} else {
		addRestrictions(b, ft, d, iv.ind, iv.max, lt|eq)
	}
}

// addBranchRestrictions updates the factsTables ft with the facts learned when
// branching from Block b in direction br.
func addBranchRestrictions(ft *factsTable, b *Block, br branch) {
	c := b.Controls[0]
	switch {
	case br == negative:
		ft.booleanFalse(c)
	case br == positive:
		ft.booleanTrue(c)
	case br >= jumpTable0:
		idx := br - jumpTable0
		val := int64(idx)
		if v, off := isConstDelta(c); v != nil {
			// Establish the bound on the underlying value we're switching on,
			// not on the offset-ed value used as the jump table index.
			c = v
			val -= off
		}
		ft.newLimit(c, limit{min: val, max: val, umin: uint64(val), umax: uint64(val)})
	default:
		panic("unknown branch")
	}
}

// addRestrictions updates restrictions from the immediate
// dominating block (p) using r.
func addRestrictions(parent *Block, ft *factsTable, t domain, v, w *Value, r relation) {
	if t == 0 {
		// Trivial case: nothing to do.
		// Should not happen, but just in case.
		return
	}
	for i := domain(1); i <= t; i <<= 1 {
		if t&i == 0 {
			continue
		}
		ft.update(parent, v, w, i, r)
	}
}

func addLocalFacts(ft *factsTable, b *Block) {
	// Propagate constant ranges among values in this block.
	// We do this before the second loop so that we have the
	// most up-to-date constant bounds for isNonNegative calls.
	for {
		changed := false
		for _, v := range b.Values {
			changed = ft.flowLimit(v) || changed
		}
		if !changed {
			break
		}
	}

	// Add facts about individual operations.
	for _, v := range b.Values {
		// FIXME(go.dev/issue/68857): this loop only set up limits properly when b.Values is in topological order.
		// flowLimit can also depend on limits given by this loop which right now is not handled.
		switch v.Op {
		case OpAnd64, OpAnd32, OpAnd16, OpAnd8:
			ft.update(b, v, v.Args[0], unsigned, lt|eq)
			ft.update(b, v, v.Args[1], unsigned, lt|eq)
			if ft.isNonNegative(v.Args[0]) {
				ft.update(b, v, v.Args[0], signed, lt|eq)
			}
			if ft.isNonNegative(v.Args[1]) {
				ft.update(b, v, v.Args[1], signed, lt|eq)
			}
		case OpOr64, OpOr32, OpOr16, OpOr8:
			// TODO: investigate how to always add facts without much slowdown, see issue #57959
			//ft.update(b, v, v.Args[0], unsigned, gt|eq)
			//ft.update(b, v, v.Args[1], unsigned, gt|eq)
		case OpDiv64u, OpDiv32u, OpDiv16u, OpDiv8u,
			OpRsh8Ux64, OpRsh8Ux32, OpRsh8Ux16, OpRsh8Ux8,
			OpRsh16Ux64, OpRsh16Ux32, OpRsh16Ux16, OpRsh16Ux8,
			OpRsh32Ux64, OpRsh32Ux32, OpRsh32Ux16, OpRsh32Ux8,
			OpRsh64Ux64, OpRsh64Ux32, OpRsh64Ux16, OpRsh64Ux8:
			ft.update(b, v, v.Args[0], unsigned, lt|eq)
		case OpMod64u, OpMod32u, OpMod16u, OpMod8u:
			ft.update(b, v, v.Args[0], unsigned, lt|eq)
			// Note: we have to be careful that this doesn't imply
			// that the modulus is >0, which isn't true until *after*
			// the mod instruction executes (and thus panics if the
			// modulus is 0). See issue 67625.
			ft.update(b, v, v.Args[1], unsigned, lt)
		case OpSliceLen:
			if v.Args[0].Op == OpSliceMake {
				ft.update(b, v, v.Args[0].Args[1], signed, eq)
			}
		case OpSliceCap:
			if v.Args[0].Op == OpSliceMake {
				ft.update(b, v, v.Args[0].Args[2], signed, eq)
			}
		case OpPhi:
			addLocalFactsPhi(ft, v)
		}
	}
}

func addLocalFactsPhi(ft *factsTable, v *Value) {
	// Look for phis that implement min/max.
	//   z:
	//      c = Less64 x y (or other Less/Leq operation)
	//      If c -> bx by
	//   bx: <- z
	//       -> b ...
	//   by: <- z
	//      -> b ...
	//   b: <- bx by
	//      v = Phi x y
	// Then v is either min or max of x,y.
	// If it is the min, then we deduce v <= x && v <= y.
	// If it is the max, then we deduce v >= x && v >= y.
	// The min case is useful for the copy builtin, see issue 16833.
	if len(v.Args) != 2 {
		return
	}
	b := v.Block
	x := v.Args[0]
	y := v.Args[1]
	bx := b.Preds[0].b
	by := b.Preds[1].b
	var z *Block // branch point
	switch {
	case bx == by: // bx == by == z case
		z = bx
	case by.uniquePred() == bx: // bx == z case
		z = bx
	case bx.uniquePred() == by: // by == z case
		z = by
	case bx.uniquePred() == by.uniquePred():
		z = bx.uniquePred()
	}
	if z == nil || z.Kind != BlockIf {
		return
	}
	c := z.Controls[0]
	if len(c.Args) != 2 {
		return
	}
	var isMin bool // if c, a less-than comparison, is true, phi chooses x.
	if bx == z {
		isMin = b.Preds[0].i == 0
	} else {
		isMin = bx.Preds[0].i == 0
	}
	if c.Args[0] == x && c.Args[1] == y {
		// ok
	} else if c.Args[0] == y && c.Args[1] == x {
		// Comparison is reversed from how the values are listed in the Phi.
		isMin = !isMin
	} else {
		// Not comparing x and y.
		return
	}
	var dom domain
	switch c.Op {
	case OpLess64, OpLess32, OpLess16, OpLess8, OpLeq64, OpLeq32, OpLeq16, OpLeq8:
		dom = signed
	case OpLess64U, OpLess32U, OpLess16U, OpLess8U, OpLeq64U, OpLeq32U, OpLeq16U, OpLeq8U:
		dom = unsigned
	default:
		return
	}
	var rel relation
	if isMin {
		rel = lt | eq
	} else {
		rel = gt | eq
	}
	ft.update(b, v, x, dom, rel)
	ft.update(b, v, y, dom, rel)
}

var ctzNonZeroOp = map[Op]Op{OpCtz8: OpCtz8NonZero, OpCtz16: OpCtz16NonZero, OpCtz32: OpCtz32NonZero, OpCtz64: OpCtz64NonZero}
var mostNegativeDividend = map[Op]int64{
	OpDiv16: -1 << 15,
	OpMod16: -1 << 15,
	OpDiv32: -1 << 31,
	OpMod32: -1 << 31,
	OpDiv64: -1 << 63,
	OpMod64: -1 << 63}

// simplifyBlock simplifies some constant values in b and evaluates
// branches to non-uniquely dominated successors of b.
func simplifyBlock(sdom SparseTree, ft *factsTable, b *Block) {
	for _, v := range b.Values {
		switch v.Op {
		case OpSlicemask:
			// Replace OpSlicemask operations in b with constants where possible.
			x, delta := isConstDelta(v.Args[0])
			if x == nil {
				break
			}
			// slicemask(x + y)
			// if x is larger than -y (y is negative), then slicemask is -1.
			lim := ft.limits[x.ID]
			if lim.umin > uint64(-delta) {
				if v.Args[0].Op == OpAdd64 {
					v.reset(OpConst64)
				} else {
					v.reset(OpConst32)
				}
				if b.Func.pass.debug > 0 {
					b.Func.Warnl(v.Pos, "Proved slicemask not needed")
				}
				v.AuxInt = -1
			}
		case OpCtz8, OpCtz16, OpCtz32, OpCtz64:
			// On some architectures, notably amd64, we can generate much better
			// code for CtzNN if we know that the argument is non-zero.
			// Capture that information here for use in arch-specific optimizations.
			x := v.Args[0]
			lim := ft.limits[x.ID]
			if lim.umin > 0 || lim.min > 0 || lim.max < 0 {
				if b.Func.pass.debug > 0 {
					b.Func.Warnl(v.Pos, "Proved %v non-zero", v.Op)
				}
				v.Op = ctzNonZeroOp[v.Op]
			}
		case OpRsh8x8, OpRsh8x16, OpRsh8x32, OpRsh8x64,
			OpRsh16x8, OpRsh16x16, OpRsh16x32, OpRsh16x64,
			OpRsh32x8, OpRsh32x16, OpRsh32x32, OpRsh32x64,
			OpRsh64x8, OpRsh64x16, OpRsh64x32, OpRsh64x64:
			// Check whether, for a >> b, we know that a is non-negative
			// and b is all of a's bits except the MSB. If so, a is shifted to zero.
			bits := 8 * v.Args[0].Type.Size()
			if v.Args[1].isGenericIntConst() && v.Args[1].AuxInt >= bits-1 && ft.isNonNegative(v.Args[0]) {
				if b.Func.pass.debug > 0 {
					b.Func.Warnl(v.Pos, "Proved %v shifts to zero", v.Op)
				}
				switch bits {
				case 64:
					v.reset(OpConst64)
				case 32:
					v.reset(OpConst32)
				case 16:
					v.reset(OpConst16)
				case 8:
					v.reset(OpConst8)
				default:
					panic("unexpected integer size")
				}
				v.AuxInt = 0
				break // Be sure not to fallthrough - this is no longer OpRsh.
			}
			// If the Rsh hasn't been replaced with 0, still check if it is bounded.
			fallthrough
		case OpLsh8x8, OpLsh8x16, OpLsh8x32, OpLsh8x64,
			OpLsh16x8, OpLsh16x16, OpLsh16x32, OpLsh16x64,
			OpLsh32x8, OpLsh32x16, OpLsh32x32, OpLsh32x64,
			OpLsh64x8, OpLsh64x16, OpLsh64x32, OpLsh64x64,
			OpRsh8Ux8, OpRsh8Ux16, OpRsh8Ux32, OpRsh8Ux64,
			OpRsh16Ux8, OpRsh16Ux16, OpRsh16Ux32, OpRsh16Ux64,
			OpRsh32Ux8, OpRsh32Ux16, OpRsh32Ux32, OpRsh32Ux64,
			OpRsh64Ux8, OpRsh64Ux16, OpRsh64Ux32, OpRsh64Ux64:
			// Check whether, for a << b, we know that b
			// is strictly less than the number of bits in a.
			by := v.Args[1]
			lim := ft.limits[by.ID]
			bits := 8 * v.Args[0].Type.Size()
			if lim.umax < uint64(bits) || (lim.max < bits && ft.isNonNegative(by)) {
				v.AuxInt = 1 // see shiftIsBounded
				if b.Func.pass.debug > 0 && !by.isGenericIntConst() {
					b.Func.Warnl(v.Pos, "Proved %v bounded", v.Op)
				}
			}
		case OpDiv16, OpDiv32, OpDiv64, OpMod16, OpMod32, OpMod64:
			// On amd64 and 386 fix-up code can be avoided if we know
			//  the divisor is not -1 or the dividend > MinIntNN.
			// Don't modify AuxInt on other architectures,
			// as that can interfere with CSE.
			// TODO: add other architectures?
			if b.Func.Config.arch != "386" && b.Func.Config.arch != "amd64" {
				break
			}
			divr := v.Args[1]
			divrLim := ft.limits[divr.ID]
			divd := v.Args[0]
			divdLim := ft.limits[divd.ID]
			if divrLim.max < -1 || divrLim.min > -1 || divdLim.min > mostNegativeDividend[v.Op] {
				// See DivisionNeedsFixUp in rewrite.go.
				// v.AuxInt = 1 means we have proved both that the divisor is not -1
				// and that the dividend is not the most negative integer,
				// so we do not need to add fix-up code.
				v.AuxInt = 1
				if b.Func.pass.debug > 0 {
					b.Func.Warnl(v.Pos, "Proved %v does not need fix-up", v.Op)
				}
			}
		}
		// Fold provable constant results.
		// Helps in cases where we reuse a value after branching on its equality.
		for i, arg := range v.Args {
			lim := ft.limits[arg.ID]
			var constValue int64
			switch {
			case lim.min == lim.max:
				constValue = lim.min
			case lim.umin == lim.umax:
				constValue = int64(lim.umin)
			default:
				continue
			}
			switch arg.Op {
			case OpConst64, OpConst32, OpConst16, OpConst8, OpConstBool, OpConstNil:
				continue
			}
			typ := arg.Type
			f := b.Func
			var c *Value
			switch {
			case typ.IsBoolean():
				c = f.ConstBool(typ, constValue != 0)
			case typ.IsInteger() && typ.Size() == 1:
				c = f.ConstInt8(typ, int8(constValue))
			case typ.IsInteger() && typ.Size() == 2:
				c = f.ConstInt16(typ, int16(constValue))
			case typ.IsInteger() && typ.Size() == 4:
				c = f.ConstInt32(typ, int32(constValue))
			case typ.IsInteger() && typ.Size() == 8:
				c = f.ConstInt64(typ, constValue)
			case typ.IsPtrShaped():
				if constValue == 0 {
					c = f.ConstNil(typ)
				} else {
					// Not sure how this might happen, but if it
					// does, just skip it.
					continue
				}
			default:
				// Not sure how this might happen, but if it
				// does, just skip it.
				continue
			}
			v.SetArg(i, c)
			ft.initLimitForNewValue(c)
			if b.Fun
"""




```