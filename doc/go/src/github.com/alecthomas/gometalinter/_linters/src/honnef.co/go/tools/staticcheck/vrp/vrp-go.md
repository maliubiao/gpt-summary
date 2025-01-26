Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the Go code, what Go feature it implements, code examples, handling of command-line arguments, and common mistakes.

2. **Initial Scan for Keywords and Structures:**  Immediately look for recognizable Go constructs:
    * `package vrp`:  Indicates this code belongs to a package named `vrp`.
    * `import`:  Lists dependencies, suggesting this code interacts with SSA (Static Single Assignment) form, Go types, constants, and potentially math operations. The presence of `"honnef.co/go/tools/ssa"` is a strong indicator that this code is related to static analysis or program understanding.
    * `type Future interface`, `type Range interface`, `type Constraint interface`: Defines key abstractions. Interfaces often signify a system for handling diverse implementations.
    * `struct` definitions (e.g., `aConstraint`, `PhiConstraint`):  Concrete implementations of the interfaces.
    * Functions starting with `New...`: Factory functions, used to create instances of the defined types.
    * Method definitions (e.g., `(c *PhiConstraint) Operands()`):  Behavior associated with the defined types.
    * Functions like `BuildGraph`, `Solve`: Core logic of the package.

3. **Infer the High-Level Purpose:** The presence of `Constraint`, `Range`, `Future`, and the interaction with `ssa.Value` strongly suggest this code is about **Value Range Propagation (VRP)**. This is further reinforced by the package name "vrp". VRP is a static analysis technique to determine the possible range of values that variables can take during program execution.

4. **Dissect Key Components:**

    * **`Future`:** Represents a constraint whose resolution depends on other factors. The methods like `Resolve`, `IsKnown`, `IsResolved` confirm this.
    * **`Range`:** Represents a set of possible values. The `Union` method indicates combining ranges.
    * **`Constraint`:**  A relationship between variables that limits their possible values. `Eval` suggests evaluating the constraint to determine a range. `Operands` hints at the variables involved in the constraint.
    * **Concrete Constraints (e.g., `PhiConstraint`):** Implement specific types of constraints. A `PhiConstraint` likely represents the merging of values at a control-flow merge point in the SSA graph.
    * **`Graph`:**  A data structure to represent the relationships between variables and constraints. The `AddEdge` and `FindSCCs` methods suggest a graph-based approach, likely using concepts like strongly connected components.
    * **`BuildGraph`:**  The function that constructs the graph from an SSA function. It iterates through instructions and creates constraints based on the operations.
    * **`Solve`:**  The core algorithm to compute the value ranges. It seems to involve iterative refinement (widening and narrowing) and handling of futures.

5. **Identify the Go Feature:** Based on the inference of VRP and the use of SSA, the core Go feature being implemented is **static analysis for value range propagation**.

6. **Construct Code Examples (Conceptual):**  Illustrate how the different constraint types might work. Focus on simple cases that demonstrate the core idea. For example, a simple integer addition constraint or a string concatenation constraint.

7. **Analyze Command-Line Arguments:**  Carefully read the code for any explicit handling of `os.Args` or flags. In this snippet, there's *no* direct handling of command-line arguments. State this clearly.

8. **Identify Potential Pitfalls:** Think about how users might misuse or misunderstand the purpose of this code. Consider:
    * **Unsupported Operations:** The code explicitly handles certain operations and ignores others. Users might expect it to handle everything.
    * **Complexity of Analysis:**  VRP can be complex. Users might misunderstand the limitations or accuracy of the analysis.
    * **Assumptions about Input:** The code works on SSA form. Users need to understand this input requirement.

9. **Structure the Answer:** Organize the information logically with clear headings. Use bullet points for listing features and potential errors. Provide concise code examples.

10. **Review and Refine:** Read through the answer to ensure clarity, accuracy, and completeness. Check for any jargon that needs explanation. Make sure the examples are easy to understand. For instance, initially, I might have focused too much on the graph algorithms, but the core functionality is about analyzing value ranges based on Go's semantics. Refocusing the explanation accordingly is important.

**Self-Correction Example During the Process:**

Initially, I might have been too focused on the graph algorithms (SCCs, Tarjan's algorithm). While important for the implementation, it's not the core *functionality* from the user's perspective. The core functionality is the *value range analysis*. I would then shift my focus in the explanation to highlight the different types of constraints and how they contribute to determining the range of values. The graph is an *implementation detail* to efficiently manage these constraints.

Similarly, if I didn't find any command-line argument handling, I would explicitly state that rather than just omitting it. This provides a complete picture.

By following this structured approach, combining code inspection with domain knowledge (static analysis), and iteratively refining the explanation, a comprehensive and accurate answer can be constructed.
这段代码是 Go 语言实现的 **值范围分析 (Value Range Propagation, VRP)** 的一部分。它的主要功能是构建和解决一个约束图，用于推断程序中变量可能取值的范围。

以下是代码的具体功能分解：

**1. 定义了核心的数据结构：**

* **`Future` 接口:**  代表一个尚未完全确定的约束，它依赖于其他变量的值。可以理解为一种延迟计算的约束。
* **`Range` 接口:** 代表一个值的范围，例如整数的区间、字符串的长度区间等。
* **`Constraint` 接口:**  代表一个变量的取值约束。不同的约束类型会对变量的取值施加不同的限制。
* **具体的约束类型:**  例如 `aConstraint` (基础约束), `PhiConstraint` (用于处理控制流汇合点), `IntIntervalConstraint` (整数区间约束), `StringIntervalConstraint` (字符串长度区间约束) 等等。
* **`Graph` 结构体:**  表示约束图，包含节点 (变量和约束) 和边 (变量与约束之间的依赖关系)。

**2. 实现了各种类型的约束:**

代码中定义了多种具体的约束类型，用于表示 Go 语言中不同操作对变量取值范围的影响。例如：

* **算术运算约束 (例如 `IntAddConstraint`, `IntSubConstraint`, `IntMulConstraint`):**  根据操作数的范围推断结果的范围。
* **比较运算约束 (通过 `Sigma` 指令处理):**  根据比较的结果限制变量的范围。
* **类型转换约束 (`IntConversionConstraint`):**  类型转换可能导致值范围的变化。
* **内置函数约束 (例如 `StringLengthConstraint`, `SliceLengthConstraint`, `MakeChannelConstraint`, `MakeSliceConstraint`):**  内置函数会产生具有特定范围的值。
* **字符串操作约束 (例如 `StringConcatConstraint`, `StringSliceConstraint`):**  字符串操作会影响字符串的长度范围。
* **切片操作约束 (例如 `SliceSliceConstraint`, `SliceAppendConstraint`):**  切片操作会影响切片的长度范围。
* **`PhiConstraint`:**  用于处理 SSA (Static Single Assignment) 形式中的 `phi` 函数，它表示在控制流汇合点，变量可能来自不同的前驱路径，因此它的取值范围是所有可能来源的并集。
* **`CopyConstraint`:**  表示一个变量的值直接复制自另一个变量。

**3. 构建约束图 (`BuildGraph` 函数):**

`BuildGraph` 函数接收一个 SSA 形式的函数 (`*ssa.Function`) 作为输入，并构建出表示值范围关系的图。

* 它遍历函数的所有基本块和指令。
* 对于每个指令，它会根据指令的类型创建相应的约束。
* 例如，如果遇到一个加法运算 (`ssa.BinOp` 且操作符是 `token.ADD`)，它会创建一个 `IntAddConstraint`。
* 它还会处理常量 (`ssa.Const`)，为其创建初始的取值范围约束。
* 它创建图的节点 (变量和约束) 和边 (表示依赖关系)。如果变量 `A` 是约束 `C` 的操作数，则图中存在从 `A` 到 `C` 的边。

**4. 解决约束图 (`Solve` 函数):**

`Solve` 函数利用构建好的约束图来推断每个变量的可能取值范围。

* 它使用一种迭代的算法，不断地传播和收紧变量的取值范围。
* 它利用强连通分量 (SCC) 来优化求解过程。在一个 SCC 内的变量和约束相互依赖，需要一起求解。
* 它使用了 **widening** 和 **narrowing** 技术：
    * **Widening:**  当迭代次数过多时，为了防止无限循环，可能会放宽变量的取值范围。
    * **Narrowing:**  根据约束逐步缩小变量的取值范围。
* 它处理 `Future` 类型的约束，在依赖的变量范围确定后，才能解析 `Future` 约束。

**它可以被推理为 Go 语言的静态分析功能，用于确定变量的取值范围。**

**Go 代码示例 (概念性):**

假设有以下简单的 Go 代码片段：

```go
package main

func foo(a int) int {
	b := a + 5
	if b > 10 {
		return b - 2
	}
	return b + 1
}

func main() {
	result := foo(3)
	println(result) // 理论上，通过 VRP 可以推断出 result 的范围
}
```

`vrp.go` 中的代码会分析 `foo` 函数的 SSA 表示，并创建如下类型的约束 (简化)：

* 对于 `b := a + 5`，创建一个 `IntAddConstraint`，将 `a` 的范围与常量 `5` 相加。
* 对于 `b > 10` 的条件，创建一个与比较操作相关的约束，根据条件成立或不成立分别限制 `b` 的范围。
* 对于 `return b - 2` 和 `return b + 1`，创建算术运算约束。
* 对于 `result := foo(3)`，由于 `a` 的初始值为常量 `3`，可以创建一个初始的整数区间约束 `[3, 3]`。

`Solve` 函数会根据这些约束迭代计算，最终可能推断出 `result` 的取值范围。

**假设的输入与输出 (针对上面的 `foo` 函数):**

**输入 (SSA 表示，简化):**

```
func foo(a int):
  b0:
    b = a + 5
    if b > 10 goto b1 else b2
  b1:
    ret b - 2
  b2:
    ret b + 1
```

**假设 VRP 分析的输出 (范围):**

* `a`: `[3, 3]` (因为 `main` 函数中调用 `foo` 时传入的是常量 `3`)
* `b` (在 `b0` 块): `[8, 8]` (3 + 5)
* `b` (在 `b1` 块，`b > 10` 条件成立): 大于 10，结合之前的范围，实际上不会到达这里
* `b` (在 `b2` 块，`b <= 10` 条件成立): 小于等于 10，结合之前的范围，`b` 仍然是 8
* `return` (在 `b1` 块):  如果能到达，范围是 `b - 2`，即大于 8
* `return` (在 `b2` 块): 范围是 `b + 1`，即 `9`
* `result`: `[9, 9]` (因为 `foo(3)` 总是返回 9)

**命令行参数处理:**

这段代码本身**没有直接处理命令行参数**。它是一个库，通常会被其他工具或程序调用。调用它的程序可能会有自己的命令行参数处理逻辑，用于指定要分析的 Go 代码路径等。

**使用者易犯错的点 (如果作为库使用):**

* **理解 SSA 形式:**  使用者需要理解 VRP 是在 SSA 形式上进行的，因此需要将 Go 代码转换为 SSA 才能使用这个库进行分析。
* **支持的操作和类型有限:** 代码中只处理了部分 Go 语言的特性和类型。如果分析的代码中包含了不支持的操作或类型，VRP 分析可能无法提供准确的范围信息或者直接跳过。例如，代码中对 `QUO`, `REM`, `SHL`, `SHR` 等位运算的约束处理是注释掉的。
* **精度损失:**  由于 VRP 是一种静态分析，它需要在保证安全性的前提下估算变量的范围。在某些复杂情况下，可能会导致一定的精度损失，即推断出的范围可能比实际运行时的范围更大。
* **循环和递归:**  对于包含复杂循环或递归的程序，VRP 的分析可能会比较复杂，需要使用 widening 等技术来保证分析的终止，但也可能牺牲一定的精度。

总而言之，这段 `vrp.go` 代码是实现 Go 语言值范围分析的核心部分，它通过构建和解决约束图来静态地推断程序中变量可能的取值范围，这对于编译器优化、错误检测等静态分析任务非常有用。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/staticcheck/vrp/vrp.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package vrp

// TODO(dh) widening and narrowing have a lot of code in common. Make
// it reusable.

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"math/big"
	"sort"
	"strings"

	"honnef.co/go/tools/ssa"
)

type Future interface {
	Constraint
	Futures() []ssa.Value
	Resolve()
	IsKnown() bool
	MarkUnresolved()
	MarkResolved()
	IsResolved() bool
}

type Range interface {
	Union(other Range) Range
	IsKnown() bool
}

type Constraint interface {
	Y() ssa.Value
	isConstraint()
	String() string
	Eval(*Graph) Range
	Operands() []ssa.Value
}

type aConstraint struct {
	y ssa.Value
}

func NewConstraint(y ssa.Value) aConstraint {
	return aConstraint{y}
}

func (aConstraint) isConstraint()  {}
func (c aConstraint) Y() ssa.Value { return c.y }

type PhiConstraint struct {
	aConstraint
	Vars []ssa.Value
}

func NewPhiConstraint(vars []ssa.Value, y ssa.Value) Constraint {
	uniqm := map[ssa.Value]struct{}{}
	for _, v := range vars {
		uniqm[v] = struct{}{}
	}
	var uniq []ssa.Value
	for v := range uniqm {
		uniq = append(uniq, v)
	}
	return &PhiConstraint{
		aConstraint: NewConstraint(y),
		Vars:        uniq,
	}
}

func (c *PhiConstraint) Operands() []ssa.Value {
	return c.Vars
}

func (c *PhiConstraint) Eval(g *Graph) Range {
	i := Range(nil)
	for _, v := range c.Vars {
		i = g.Range(v).Union(i)
	}
	return i
}

func (c *PhiConstraint) String() string {
	names := make([]string, len(c.Vars))
	for i, v := range c.Vars {
		names[i] = v.Name()
	}
	return fmt.Sprintf("%s = φ(%s)", c.Y().Name(), strings.Join(names, ", "))
}

func isSupportedType(typ types.Type) bool {
	switch typ := typ.Underlying().(type) {
	case *types.Basic:
		switch typ.Kind() {
		case types.String, types.UntypedString:
			return true
		default:
			if (typ.Info() & types.IsInteger) == 0 {
				return false
			}
		}
	case *types.Chan:
		return true
	case *types.Slice:
		return true
	default:
		return false
	}
	return true
}

func ConstantToZ(c constant.Value) Z {
	s := constant.ToInt(c).ExactString()
	n := &big.Int{}
	n.SetString(s, 10)
	return NewBigZ(n)
}

func sigmaInteger(g *Graph, ins *ssa.Sigma, cond *ssa.BinOp, ops []*ssa.Value) Constraint {
	op := cond.Op
	if !ins.Branch {
		op = (invertToken(op))
	}

	switch op {
	case token.EQL, token.GTR, token.GEQ, token.LSS, token.LEQ:
	default:
		return nil
	}
	var a, b ssa.Value
	if (*ops[0]) == ins.X {
		a = *ops[0]
		b = *ops[1]
	} else {
		a = *ops[1]
		b = *ops[0]
		op = flipToken(op)
	}
	return NewIntIntersectionConstraint(a, b, op, g.ranges, ins)
}

func sigmaString(g *Graph, ins *ssa.Sigma, cond *ssa.BinOp, ops []*ssa.Value) Constraint {
	op := cond.Op
	if !ins.Branch {
		op = (invertToken(op))
	}

	switch op {
	case token.EQL, token.GTR, token.GEQ, token.LSS, token.LEQ:
	default:
		return nil
	}

	if ((*ops[0]).Type().Underlying().(*types.Basic).Info() & types.IsString) == 0 {
		var a, b ssa.Value
		call, ok := (*ops[0]).(*ssa.Call)
		if ok && call.Common().Args[0] == ins.X {
			a = *ops[0]
			b = *ops[1]
		} else {
			a = *ops[1]
			b = *ops[0]
			op = flipToken(op)
		}
		return NewStringIntersectionConstraint(a, b, op, g.ranges, ins)
	}
	var a, b ssa.Value
	if (*ops[0]) == ins.X {
		a = *ops[0]
		b = *ops[1]
	} else {
		a = *ops[1]
		b = *ops[0]
		op = flipToken(op)
	}
	return NewStringIntersectionConstraint(a, b, op, g.ranges, ins)
}

func sigmaSlice(g *Graph, ins *ssa.Sigma, cond *ssa.BinOp, ops []*ssa.Value) Constraint {
	// TODO(dh) sigmaSlice and sigmaString are a lot alike. Can they
	// be merged?
	//
	// XXX support futures

	op := cond.Op
	if !ins.Branch {
		op = (invertToken(op))
	}

	k, ok := (*ops[1]).(*ssa.Const)
	// XXX investigate in what cases this wouldn't be a Const
	//
	// XXX what if left and right are swapped?
	if !ok {
		return nil
	}

	call, ok := (*ops[0]).(*ssa.Call)
	if !ok {
		return nil
	}
	builtin, ok := call.Common().Value.(*ssa.Builtin)
	if !ok {
		return nil
	}
	if builtin.Name() != "len" {
		return nil
	}
	callops := call.Operands(nil)

	v := ConstantToZ(k.Value)
	c := NewSliceIntersectionConstraint(*callops[1], IntInterval{}, ins).(*SliceIntersectionConstraint)
	switch op {
	case token.EQL:
		c.I = NewIntInterval(v, v)
	case token.GTR, token.GEQ:
		off := int64(0)
		if cond.Op == token.GTR {
			off = 1
		}
		c.I = NewIntInterval(
			v.Add(NewZ(off)),
			PInfinity,
		)
	case token.LSS, token.LEQ:
		off := int64(0)
		if cond.Op == token.LSS {
			off = -1
		}
		c.I = NewIntInterval(
			NInfinity,
			v.Add(NewZ(off)),
		)
	default:
		return nil
	}
	return c
}

func BuildGraph(f *ssa.Function) *Graph {
	g := &Graph{
		Vertices: map[interface{}]*Vertex{},
		ranges:   Ranges{},
	}

	var cs []Constraint

	ops := make([]*ssa.Value, 16)
	seen := map[ssa.Value]bool{}
	for _, block := range f.Blocks {
		for _, ins := range block.Instrs {
			ops = ins.Operands(ops[:0])
			for _, op := range ops {
				if c, ok := (*op).(*ssa.Const); ok {
					if seen[c] {
						continue
					}
					seen[c] = true
					if c.Value == nil {
						switch c.Type().Underlying().(type) {
						case *types.Slice:
							cs = append(cs, NewSliceIntervalConstraint(NewIntInterval(NewZ(0), NewZ(0)), c))
						}
						continue
					}
					switch c.Value.Kind() {
					case constant.Int:
						v := ConstantToZ(c.Value)
						cs = append(cs, NewIntIntervalConstraint(NewIntInterval(v, v), c))
					case constant.String:
						s := constant.StringVal(c.Value)
						n := NewZ(int64(len(s)))
						cs = append(cs, NewStringIntervalConstraint(NewIntInterval(n, n), c))
					}
				}
			}
		}
	}
	for _, block := range f.Blocks {
		for _, ins := range block.Instrs {
			switch ins := ins.(type) {
			case *ssa.Convert:
				switch v := ins.Type().Underlying().(type) {
				case *types.Basic:
					if (v.Info() & types.IsInteger) == 0 {
						continue
					}
					cs = append(cs, NewIntConversionConstraint(ins.X, ins))
				}
			case *ssa.Call:
				if static := ins.Common().StaticCallee(); static != nil {
					if fn, ok := static.Object().(*types.Func); ok {
						switch fn.FullName() {
						case "bytes.Index", "bytes.IndexAny", "bytes.IndexByte",
							"bytes.IndexFunc", "bytes.IndexRune", "bytes.LastIndex",
							"bytes.LastIndexAny", "bytes.LastIndexByte", "bytes.LastIndexFunc",
							"strings.Index", "strings.IndexAny", "strings.IndexByte",
							"strings.IndexFunc", "strings.IndexRune", "strings.LastIndex",
							"strings.LastIndexAny", "strings.LastIndexByte", "strings.LastIndexFunc":
							// TODO(dh): instead of limiting by +∞,
							// limit by the upper bound of the passed
							// string
							cs = append(cs, NewIntIntervalConstraint(NewIntInterval(NewZ(-1), PInfinity), ins))
						case "bytes.Title", "bytes.ToLower", "bytes.ToTitle", "bytes.ToUpper",
							"strings.Title", "strings.ToLower", "strings.ToTitle", "strings.ToUpper":
							cs = append(cs, NewCopyConstraint(ins.Common().Args[0], ins))
						case "bytes.ToLowerSpecial", "bytes.ToTitleSpecial", "bytes.ToUpperSpecial",
							"strings.ToLowerSpecial", "strings.ToTitleSpecial", "strings.ToUpperSpecial":
							cs = append(cs, NewCopyConstraint(ins.Common().Args[1], ins))
						case "bytes.Compare", "strings.Compare":
							cs = append(cs, NewIntIntervalConstraint(NewIntInterval(NewZ(-1), NewZ(1)), ins))
						case "bytes.Count", "strings.Count":
							// TODO(dh): instead of limiting by +∞,
							// limit by the upper bound of the passed
							// string.
							cs = append(cs, NewIntIntervalConstraint(NewIntInterval(NewZ(0), PInfinity), ins))
						case "bytes.Map", "bytes.TrimFunc", "bytes.TrimLeft", "bytes.TrimLeftFunc",
							"bytes.TrimRight", "bytes.TrimRightFunc", "bytes.TrimSpace",
							"strings.Map", "strings.TrimFunc", "strings.TrimLeft", "strings.TrimLeftFunc",
							"strings.TrimRight", "strings.TrimRightFunc", "strings.TrimSpace":
							// TODO(dh): lower = 0, upper = upper of passed string
						case "bytes.TrimPrefix", "bytes.TrimSuffix",
							"strings.TrimPrefix", "strings.TrimSuffix":
							// TODO(dh) range between "unmodified" and len(cutset) removed
						case "(*bytes.Buffer).Cap", "(*bytes.Buffer).Len", "(*bytes.Reader).Len", "(*bytes.Reader).Size":
							cs = append(cs, NewIntIntervalConstraint(NewIntInterval(NewZ(0), PInfinity), ins))
						}
					}
				}
				builtin, ok := ins.Common().Value.(*ssa.Builtin)
				ops := ins.Operands(nil)
				if !ok {
					continue
				}
				switch builtin.Name() {
				case "len":
					switch op1 := (*ops[1]).Type().Underlying().(type) {
					case *types.Basic:
						if op1.Kind() == types.String || op1.Kind() == types.UntypedString {
							cs = append(cs, NewStringLengthConstraint(*ops[1], ins))
						}
					case *types.Slice:
						cs = append(cs, NewSliceLengthConstraint(*ops[1], ins))
					}

				case "append":
					cs = append(cs, NewSliceAppendConstraint(ins.Common().Args[0], ins.Common().Args[1], ins))
				}
			case *ssa.BinOp:
				ops := ins.Operands(nil)
				basic, ok := (*ops[0]).Type().Underlying().(*types.Basic)
				if !ok {
					continue
				}
				switch basic.Kind() {
				case types.Int, types.Int8, types.Int16, types.Int32, types.Int64,
					types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64, types.UntypedInt:
					fns := map[token.Token]func(ssa.Value, ssa.Value, ssa.Value) Constraint{
						token.ADD: NewIntAddConstraint,
						token.SUB: NewIntSubConstraint,
						token.MUL: NewIntMulConstraint,
						// XXX support QUO, REM, SHL, SHR
					}
					fn, ok := fns[ins.Op]
					if ok {
						cs = append(cs, fn(*ops[0], *ops[1], ins))
					}
				case types.String, types.UntypedString:
					if ins.Op == token.ADD {
						cs = append(cs, NewStringConcatConstraint(*ops[0], *ops[1], ins))
					}
				}
			case *ssa.Slice:
				typ := ins.X.Type().Underlying()
				switch typ := typ.(type) {
				case *types.Basic:
					cs = append(cs, NewStringSliceConstraint(ins.X, ins.Low, ins.High, ins))
				case *types.Slice:
					cs = append(cs, NewSliceSliceConstraint(ins.X, ins.Low, ins.High, ins))
				case *types.Array:
					cs = append(cs, NewArraySliceConstraint(ins.X, ins.Low, ins.High, ins))
				case *types.Pointer:
					if _, ok := typ.Elem().(*types.Array); !ok {
						continue
					}
					cs = append(cs, NewArraySliceConstraint(ins.X, ins.Low, ins.High, ins))
				}
			case *ssa.Phi:
				if !isSupportedType(ins.Type()) {
					continue
				}
				ops := ins.Operands(nil)
				dops := make([]ssa.Value, len(ops))
				for i, op := range ops {
					dops[i] = *op
				}
				cs = append(cs, NewPhiConstraint(dops, ins))
			case *ssa.Sigma:
				pred := ins.Block().Preds[0]
				instrs := pred.Instrs
				cond, ok := instrs[len(instrs)-1].(*ssa.If).Cond.(*ssa.BinOp)
				ops := cond.Operands(nil)
				if !ok {
					continue
				}
				switch typ := ins.Type().Underlying().(type) {
				case *types.Basic:
					var c Constraint
					switch typ.Kind() {
					case types.Int, types.Int8, types.Int16, types.Int32, types.Int64,
						types.Uint, types.Uint8, types.Uint16, types.Uint32, types.Uint64, types.UntypedInt:
						c = sigmaInteger(g, ins, cond, ops)
					case types.String, types.UntypedString:
						c = sigmaString(g, ins, cond, ops)
					}
					if c != nil {
						cs = append(cs, c)
					}
				case *types.Slice:
					c := sigmaSlice(g, ins, cond, ops)
					if c != nil {
						cs = append(cs, c)
					}
				default:
					//log.Printf("unsupported sigma type %T", typ) // XXX
				}
			case *ssa.MakeChan:
				cs = append(cs, NewMakeChannelConstraint(ins.Size, ins))
			case *ssa.MakeSlice:
				cs = append(cs, NewMakeSliceConstraint(ins.Len, ins))
			case *ssa.ChangeType:
				switch ins.X.Type().Underlying().(type) {
				case *types.Chan:
					cs = append(cs, NewChannelChangeTypeConstraint(ins.X, ins))
				}
			}
		}
	}

	for _, c := range cs {
		if c == nil {
			panic("nil constraint")
		}
		// If V is used in constraint C, then we create an edge V->C
		for _, op := range c.Operands() {
			g.AddEdge(op, c, false)
		}
		if c, ok := c.(Future); ok {
			for _, op := range c.Futures() {
				g.AddEdge(op, c, true)
			}
		}
		// If constraint C defines variable V, then we create an edge
		// C->V
		g.AddEdge(c, c.Y(), false)
	}

	g.FindSCCs()
	g.sccEdges = make([][]Edge, len(g.SCCs))
	g.futures = make([][]Future, len(g.SCCs))
	for _, e := range g.Edges {
		g.sccEdges[e.From.SCC] = append(g.sccEdges[e.From.SCC], e)
		if !e.control {
			continue
		}
		if c, ok := e.To.Value.(Future); ok {
			g.futures[e.From.SCC] = append(g.futures[e.From.SCC], c)
		}
	}
	return g
}

func (g *Graph) Solve() Ranges {
	var consts []Z
	off := NewZ(1)
	for _, n := range g.Vertices {
		if c, ok := n.Value.(*ssa.Const); ok {
			basic, ok := c.Type().Underlying().(*types.Basic)
			if !ok {
				continue
			}
			if (basic.Info() & types.IsInteger) != 0 {
				z := ConstantToZ(c.Value)
				consts = append(consts, z)
				consts = append(consts, z.Add(off))
				consts = append(consts, z.Sub(off))
			}
		}

	}
	sort.Sort(Zs(consts))

	for scc, vertices := range g.SCCs {
		n := 0
		n = len(vertices)
		if n == 1 {
			g.resolveFutures(scc)
			v := vertices[0]
			if v, ok := v.Value.(ssa.Value); ok {
				switch typ := v.Type().Underlying().(type) {
				case *types.Basic:
					switch typ.Kind() {
					case types.String, types.UntypedString:
						if !g.Range(v).(StringInterval).IsKnown() {
							g.SetRange(v, StringInterval{NewIntInterval(NewZ(0), PInfinity)})
						}
					default:
						if !g.Range(v).(IntInterval).IsKnown() {
							g.SetRange(v, InfinityFor(v))
						}
					}
				case *types.Chan:
					if !g.Range(v).(ChannelInterval).IsKnown() {
						g.SetRange(v, ChannelInterval{NewIntInterval(NewZ(0), PInfinity)})
					}
				case *types.Slice:
					if !g.Range(v).(SliceInterval).IsKnown() {
						g.SetRange(v, SliceInterval{NewIntInterval(NewZ(0), PInfinity)})
					}
				}
			}
			if c, ok := v.Value.(Constraint); ok {
				g.SetRange(c.Y(), c.Eval(g))
			}
		} else {
			uses := g.uses(scc)
			entries := g.entries(scc)
			for len(entries) > 0 {
				v := entries[len(entries)-1]
				entries = entries[:len(entries)-1]
				for _, use := range uses[v] {
					if g.widen(use, consts) {
						entries = append(entries, use.Y())
					}
				}
			}

			g.resolveFutures(scc)

			// XXX this seems to be necessary, but shouldn't be.
			// removing it leads to nil pointer derefs; investigate
			// where we're not setting values correctly.
			for _, n := range vertices {
				if v, ok := n.Value.(ssa.Value); ok {
					i, ok := g.Range(v).(IntInterval)
					if !ok {
						continue
					}
					if !i.IsKnown() {
						g.SetRange(v, InfinityFor(v))
					}
				}
			}

			actives := g.actives(scc)
			for len(actives) > 0 {
				v := actives[len(actives)-1]
				actives = actives[:len(actives)-1]
				for _, use := range uses[v] {
					if g.narrow(use) {
						actives = append(actives, use.Y())
					}
				}
			}
		}
		// propagate scc
		for _, edge := range g.sccEdges[scc] {
			if edge.control {
				continue
			}
			if edge.From.SCC == edge.To.SCC {
				continue
			}
			if c, ok := edge.To.Value.(Constraint); ok {
				g.SetRange(c.Y(), c.Eval(g))
			}
			if c, ok := edge.To.Value.(Future); ok {
				if !c.IsKnown() {
					c.MarkUnresolved()
				}
			}
		}
	}

	for v, r := range g.ranges {
		i, ok := r.(IntInterval)
		if !ok {
			continue
		}
		if (v.Type().Underlying().(*types.Basic).Info() & types.IsUnsigned) == 0 {
			if i.Upper != PInfinity {
				s := &types.StdSizes{
					// XXX is it okay to assume the largest word size, or do we
					// need to be platform specific?
					WordSize: 8,
					MaxAlign: 1,
				}
				bits := (s.Sizeof(v.Type()) * 8) - 1
				n := big.NewInt(1)
				n = n.Lsh(n, uint(bits))
				upper, lower := &big.Int{}, &big.Int{}
				upper.Sub(n, big.NewInt(1))
				lower.Neg(n)

				if i.Upper.Cmp(NewBigZ(upper)) == 1 {
					i = NewIntInterval(NInfinity, PInfinity)
				} else if i.Lower.Cmp(NewBigZ(lower)) == -1 {
					i = NewIntInterval(NInfinity, PInfinity)
				}
			}
		}

		g.ranges[v] = i
	}

	return g.ranges
}

func VertexString(v *Vertex) string {
	switch v := v.Value.(type) {
	case Constraint:
		return v.String()
	case ssa.Value:
		return v.Name()
	case nil:
		return "BUG: nil vertex value"
	default:
		panic(fmt.Sprintf("unexpected type %T", v))
	}
}

type Vertex struct {
	Value   interface{} // one of Constraint or ssa.Value
	SCC     int
	index   int
	lowlink int
	stack   bool

	Succs []Edge
}

type Ranges map[ssa.Value]Range

func (r Ranges) Get(x ssa.Value) Range {
	if x == nil {
		return nil
	}
	i, ok := r[x]
	if !ok {
		switch x := x.Type().Underlying().(type) {
		case *types.Basic:
			switch x.Kind() {
			case types.String, types.UntypedString:
				return StringInterval{}
			default:
				return IntInterval{}
			}
		case *types.Chan:
			return ChannelInterval{}
		case *types.Slice:
			return SliceInterval{}
		}
	}
	return i
}

type Graph struct {
	Vertices map[interface{}]*Vertex
	Edges    []Edge
	SCCs     [][]*Vertex
	ranges   Ranges

	// map SCCs to futures
	futures [][]Future
	// map SCCs to edges
	sccEdges [][]Edge
}

func (g Graph) Graphviz() string {
	var lines []string
	lines = append(lines, "digraph{")
	ids := map[interface{}]int{}
	i := 1
	for _, v := range g.Vertices {
		ids[v] = i
		shape := "box"
		if _, ok := v.Value.(ssa.Value); ok {
			shape = "oval"
		}
		lines = append(lines, fmt.Sprintf(`n%d [shape="%s", label=%q, colorscheme=spectral11, style="filled", fillcolor="%d"]`,
			i, shape, VertexString(v), (v.SCC%11)+1))
		i++
	}
	for _, e := range g.Edges {
		style := "solid"
		if e.control {
			style = "dashed"
		}
		lines = append(lines, fmt.Sprintf(`n%d -> n%d [style="%s"]`, ids[e.From], ids[e.To], style))
	}
	lines = append(lines, "}")
	return strings.Join(lines, "\n")
}

func (g *Graph) SetRange(x ssa.Value, r Range) {
	g.ranges[x] = r
}

func (g *Graph) Range(x ssa.Value) Range {
	return g.ranges.Get(x)
}

func (g *Graph) widen(c Constraint, consts []Z) bool {
	setRange := func(i Range) {
		g.SetRange(c.Y(), i)
	}
	widenIntInterval := func(oi, ni IntInterval) (IntInterval, bool) {
		if !ni.IsKnown() {
			return oi, false
		}
		nlc := NInfinity
		nuc := PInfinity
		for _, co := range consts {
			if co.Cmp(ni.Lower) <= 0 {
				nlc = co
				break
			}
		}
		for _, co := range consts {
			if co.Cmp(ni.Upper) >= 0 {
				nuc = co
				break
			}
		}

		if !oi.IsKnown() {
			return ni, true
		}
		if ni.Lower.Cmp(oi.Lower) == -1 && ni.Upper.Cmp(oi.Upper) == 1 {
			return NewIntInterval(nlc, nuc), true
		}
		if ni.Lower.Cmp(oi.Lower) == -1 {
			return NewIntInterval(nlc, oi.Upper), true
		}
		if ni.Upper.Cmp(oi.Upper) == 1 {
			return NewIntInterval(oi.Lower, nuc), true
		}
		return oi, false
	}
	switch oi := g.Range(c.Y()).(type) {
	case IntInterval:
		ni := c.Eval(g).(IntInterval)
		si, changed := widenIntInterval(oi, ni)
		if changed {
			setRange(si)
			return true
		}
		return false
	case StringInterval:
		ni := c.Eval(g).(StringInterval)
		si, changed := widenIntInterval(oi.Length, ni.Length)
		if changed {
			setRange(StringInterval{si})
			return true
		}
		return false
	case SliceInterval:
		ni := c.Eval(g).(SliceInterval)
		si, changed := widenIntInterval(oi.Length, ni.Length)
		if changed {
			setRange(SliceInterval{si})
			return true
		}
		return false
	default:
		return false
	}
}

func (g *Graph) narrow(c Constraint) bool {
	narrowIntInterval := func(oi, ni IntInterval) (IntInterval, bool) {
		oLower := oi.Lower
		oUpper := oi.Upper
		nLower := ni.Lower
		nUpper := ni.Upper

		if oLower == NInfinity && nLower != NInfinity {
			return NewIntInterval(nLower, oUpper), true
		}
		if oUpper == PInfinity && nUpper != PInfinity {
			return NewIntInterval(oLower, nUpper), true
		}
		if oLower.Cmp(nLower) == 1 {
			return NewIntInterval(nLower, oUpper), true
		}
		if oUpper.Cmp(nUpper) == -1 {
			return NewIntInterval(oLower, nUpper), true
		}
		return oi, false
	}
	switch oi := g.Range(c.Y()).(type) {
	case IntInterval:
		ni := c.Eval(g).(IntInterval)
		si, changed := narrowIntInterval(oi, ni)
		if changed {
			g.SetRange(c.Y(), si)
			return true
		}
		return false
	case StringInterval:
		ni := c.Eval(g).(StringInterval)
		si, changed := narrowIntInterval(oi.Length, ni.Length)
		if changed {
			g.SetRange(c.Y(), StringInterval{si})
			return true
		}
		return false
	case SliceInterval:
		ni := c.Eval(g).(SliceInterval)
		si, changed := narrowIntInterval(oi.Length, ni.Length)
		if changed {
			g.SetRange(c.Y(), SliceInterval{si})
			return true
		}
		return false
	default:
		return false
	}
}

func (g *Graph) resolveFutures(scc int) {
	for _, c := range g.futures[scc] {
		c.Resolve()
	}
}

func (g *Graph) entries(scc int) []ssa.Value {
	var entries []ssa.Value
	for _, n := range g.Vertices {
		if n.SCC != scc {
			continue
		}
		if v, ok := n.Value.(ssa.Value); ok {
			// XXX avoid quadratic runtime
			//
			// XXX I cannot think of any code where the future and its
			// variables aren't in the same SCC, in which case this
			// code isn't very useful (the variables won't be resolved
			// yet). Before we have a cross-SCC example, however, we
			// can't really verify that this code is working
			// correctly, or indeed doing anything useful.
			for _, on := range g.Vertices {
				if c, ok := on.Value.(Future); ok {
					if c.Y() == v {
						if !c.IsResolved() {
							g.SetRange(c.Y(), c.Eval(g))
							c.MarkResolved()
						}
						break
					}
				}
			}
			if g.Range(v).IsKnown() {
				entries = append(entries, v)
			}
		}
	}
	return entries
}

func (g *Graph) uses(scc int) map[ssa.Value][]Constraint {
	m := map[ssa.Value][]Constraint{}
	for _, e := range g.sccEdges[scc] {
		if e.control {
			continue
		}
		if v, ok := e.From.Value.(ssa.Value); ok {
			c := e.To.Value.(Constraint)
			sink := c.Y()
			if g.Vertices[sink].SCC == scc {
				m[v] = append(m[v], c)
			}
		}
	}
	return m
}

func (g *Graph) actives(scc int) []ssa.Value {
	var actives []ssa.Value
	for _, n := range g.Vertices {
		if n.SCC != scc {
			continue
		}
		if v, ok := n.Value.(ssa.Value); ok {
			if _, ok := v.(*ssa.Const); !ok {
				actives = append(actives, v)
			}
		}
	}
	return actives
}

func (g *Graph) AddEdge(from, to interface{}, ctrl bool) {
	vf, ok := g.Vertices[from]
	if !ok {
		vf = &Vertex{Value: from}
		g.Vertices[from] = vf
	}
	vt, ok := g.Vertices[to]
	if !ok {
		vt = &Vertex{Value: to}
		g.Vertices[to] = vt
	}
	e := Edge{From: vf, To: vt, control: ctrl}
	g.Edges = append(g.Edges, e)
	vf.Succs = append(vf.Succs, e)
}

type Edge struct {
	From, To *Vertex
	control  bool
}

func (e Edge) String() string {
	return fmt.Sprintf("%s -> %s", VertexString(e.From), VertexString(e.To))
}

func (g *Graph) FindSCCs() {
	// use Tarjan to find the SCCs

	index := 1
	var s []*Vertex

	scc := 0
	var strongconnect func(v *Vertex)
	strongconnect = func(v *Vertex) {
		// set the depth index for v to the smallest unused index
		v.index = index
		v.lowlink = index
		index++
		s = append(s, v)
		v.stack = true

		for _, e := range v.Succs {
			w := e.To
			if w.index == 0 {
				// successor w has not yet been visited; recurse on it
				strongconnect(w)
				if w.lowlink < v.lowlink {
					v.lowlink = w.lowlink
				}
			} else if w.stack {
				// successor w is in stack s and hence in the current scc
				if w.index < v.lowlink {
					v.lowlink = w.index
				}
			}
		}

		if v.lowlink == v.index {
			for {
				w := s[len(s)-1]
				s = s[:len(s)-1]
				w.stack = false
				w.SCC = scc
				if w == v {
					break
				}
			}
			scc++
		}
	}
	for _, v := range g.Vertices {
		if v.index == 0 {
			strongconnect(v)
		}
	}

	g.SCCs = make([][]*Vertex, scc)
	for _, n := range g.Vertices {
		n.SCC = scc - n.SCC - 1
		g.SCCs[n.SCC] = append(g.SCCs[n.SCC], n)
	}
}

func invertToken(tok token.Token) token.Token {
	switch tok {
	case token.LSS:
		return token.GEQ
	case token.GTR:
		return token.LEQ
	case token.EQL:
		return token.NEQ
	case token.NEQ:
		return token.EQL
	case token.GEQ:
		return token.LSS
	case token.LEQ:
		return token.GTR
	default:
		panic(fmt.Sprintf("unsupported token %s", tok))
	}
}

func flipToken(tok token.Token) token.Token {
	switch tok {
	case token.LSS:
		return token.GTR
	case token.GTR:
		return token.LSS
	case token.EQL:
		return token.EQL
	case token.NEQ:
		return token.NEQ
	case token.GEQ:
		return token.LEQ
	case token.LEQ:
		return token.GEQ
	default:
		panic(fmt.Sprintf("unsupported token %s", tok))
	}
}

type CopyConstraint struct {
	aConstraint
	X ssa.Value
}

func (c *CopyConstraint) String() string {
	return fmt.Sprintf("%s = copy(%s)", c.Y().Name(), c.X.Name())
}

func (c *CopyConstraint) Eval(g *Graph) Range {
	return g.Range(c.X)
}

func (c *CopyConstraint) Operands() []ssa.Value {
	return []ssa.Value{c.X}
}

func NewCopyConstraint(x, y ssa.Value) Constraint {
	return &CopyConstraint{
		aConstraint: aConstraint{
			y: y,
		},
		X: x,
	}
}

"""



```