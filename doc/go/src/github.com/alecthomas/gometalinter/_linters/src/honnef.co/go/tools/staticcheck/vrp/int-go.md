Response:
Let's break down the thought process to analyze the provided Go code.

1. **Identify the Core Purpose:** The package name `vrp` and the file name `int.go` strongly suggest this code deals with value range propagation, specifically for integer values. Looking at the `Z` and `IntInterval` types reinforces this idea.

2. **Deconstruct the Basic Data Types:**

   * **`Z`:**  This struct represents an integer, but with the crucial addition of `infinity`. This signals the ability to represent positive and negative infinity, which is essential for range analysis. The `big.Int` suggests handling arbitrarily large integers. The methods like `Add`, `Sub`, `Mul`, `Cmp`, `String`, `Sign` confirm it's designed for numerical operations, including comparisons and string representation.

   * **`Zs`:** This is simply a slice of `Z`, likely for sorting or other collection-based operations. The `Len`, `Less`, and `Swap` methods immediately point to it implementing the `sort.Interface`.

   * **`IntInterval`:** This struct represents a range of integers, defined by a lower and upper bound (both of type `Z`). The `known` field suggests the possibility of an unknown or uninitialized interval. Methods like `Intersection`, `Union`, `Add`, `Sub`, `Mul`, `Empty`, `IsMaxRange` are standard for interval arithmetic.

3. **Analyze Key Functions and Methods:**

   * **`NewZ`, `NewBigZ`:**  Constructors for creating `Z` values.
   * **`NInfinity`, `PInfinity`:** Global variables representing negative and positive infinity.
   * **Arithmetic Operations on `Z` (`Add`, `Sub`, `Mul`, `Negate`):** These implement arithmetic while handling infinity correctly (e.g., infinity + number = infinity). The `panic` statements highlight cases where operations are undefined (e.g., infinity - infinity).
   * **Comparison (`Cmp`):**  Compares two `Z` values, handling infinity.
   * **`MaxZ`, `MinZ`:** Helper functions to find the maximum or minimum of a set of `Z` values.
   * **`NewIntInterval`:** Constructor for `IntInterval`, ensuring the lower bound is not greater than the upper bound.
   * **Arithmetic Operations on `IntInterval` (`Add`, `Sub`, `Mul`):** These perform interval arithmetic, calculating the resulting interval based on the input intervals. For example, `[a, b] + [c, d] = [a+c, b+d]`. The `Mul` operation needs to consider all four combinations of the endpoints.
   * **`Intersection`, `Union`:**  Standard interval operations.
   * **`InfinityFor`:** This function determines the initial `IntInterval` for a given `ssa.Value`. It uses the type information to determine if the integer is signed or unsigned, which affects the lower bound (0 for unsigned, negative infinity for signed).
   * **Constraint Types (`IntArithmeticConstraint`, `IntConversionConstraint`, `IntIntersectionConstraint`, `IntIntervalConstraint`):** These structs represent constraints on the values of SSA values. They store information about the operation, operands, and the resulting interval. The `Eval` methods are crucial for evaluating the constraints and determining the range of the result.
   * **`Eval` methods for constraints:** These are the core logic for range propagation. They take the current ranges of the operands (from the `Graph`) and apply the constraint to calculate the resulting range. The `IntConversionConstraint` handles type conversions, and its logic considers the size and signedness of the source and destination types. The `IntIntersectionConstraint` handles conditional branches and refines the interval based on the comparison operator.
   * **`Resolve` method for `IntIntersectionConstraint`:** This method is called when the range of the compared value becomes known. It updates the interval based on the comparison operator (e.g., if `x > 5`, the lower bound is `6`).

4. **Infer the Go Language Feature:** The code strongly suggests an implementation for **Value Range Analysis** or **Interval Analysis**. This is a static analysis technique used by compilers and static analysis tools to determine the possible range of values that a variable can hold during program execution. This information can be used for various optimizations and error detection. The use of `ssa.Value` hints at its integration within a Static Single Assignment (SSA) form based analysis framework.

5. **Construct Go Code Examples:** Based on the understanding of `Z` and `IntInterval`, creating examples for arithmetic operations and comparisons becomes straightforward. The examples should illustrate how infinity is handled.

6. **Analyze Command Line Arguments (if applicable):**  The provided code snippet doesn't directly handle command-line arguments. If this were a standalone tool, it would likely use the `flag` package for this. However, given the context of `gometalinter` and static analysis, it's more likely that the input is the Go source code itself.

7. **Identify Potential User Errors:**  Since this code is part of a static analysis tool, direct "user errors" in *using* this specific code are unlikely. However,  programmers using code *analyzed* by this tool might make mistakes that this analysis could catch. Examples include potential integer overflows or accessing array indices out of bounds. These aren't errors in *using* `int.go`, but rather errors the analysis aims to *detect*.

8. **Structure the Answer:** Organize the findings into clear sections as requested by the prompt: functionalities, inferred Go feature with examples, code reasoning with input/output, command-line arguments, and common mistakes. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this is just about arbitrary-precision integers.
* **Correction:** The `infinity` field in `Z` and the `IntInterval` type strongly suggest range analysis, not just arbitrary precision. `big.Int` handles the precision aspect.
* **Initial thought:** How are the constraints actually used?
* **Refinement:** The `Eval` methods within the constraint structs and the interaction with the `Graph` (which is not fully shown but implied) reveal the process of propagating ranges through the program's SSA representation.
* **Initial thought:** What are the inputs and outputs of the `Eval` methods?
* **Refinement:** The `Eval` methods take a `Graph` (presumably holding the current ranges of variables) and return an `IntInterval`, representing the calculated range for the constrained value.

By following these steps, combining code analysis with domain knowledge (static analysis, interval arithmetic), and iteratively refining the understanding, we arrive at the comprehensive explanation provided in the initial example answer.
这段Go语言代码是 `honnef.co/go/tools/staticcheck` 工具中的一部分，位于 `vrp`（Value Range Propagation）包中，专门用于处理 **整数类型的值范围分析**。

**功能列表:**

1. **定义了表示整数的类型 `Z`:**
   - `Z` 结构体可以表示普通的整数 (使用 `big.Int` 支持任意大小的整数) 以及正负无穷 (`PInfinity` 和 `NInfinity`)。
   - 提供了创建 `Z` 值的函数 `NewZ` 和 `NewBigZ`。
   - 提供了判断是否为无穷的方法 `Infinite()`。
   - 实现了基本的算术运算（加法 `Add`、减法 `Sub`、乘法 `Mul`、取负 `Negate`），并且能够处理无穷的情况。
   - 提供了获取符号的方法 `Sign()`。
   - 提供了字符串表示方法 `String()`。
   - 实现了比较方法 `Cmp()`，用于比较两个 `Z` 值的大小，包括无穷。

2. **定义了 `Z` 类型的切片 `Zs` 并实现了排序接口:**
   - `Zs` 类型是 `Z` 的切片。
   - 实现了 `sort.Interface` 接口的 `Len`、`Less` 和 `Swap` 方法，使得可以对 `Z` 值的切片进行排序。

3. **定义了表示整数区间的类型 `IntInterval`:**
   - `IntInterval` 结构体表示一个整数的取值范围，包含一个是否已知的标志 `known`，以及下界 `Lower` 和上界 `Upper` (都是 `Z` 类型)。
   - 提供了创建 `IntInterval` 的函数 `NewIntInterval`，会自动处理下界大于上界的情况，将其视为空区间。
   - 提供了判断区间是否已知 `IsKnown()`，是否为空 `Empty()`，是否为最大范围（负无穷到正无穷）`IsMaxRange()` 的方法。
   - 实现了区间的基本操作：交集 `Intersection`、并集 `Union`。
   - 实现了区间的算术运算：加法 `Add`、减法 `Sub`、乘法 `Mul`。
   - 提供了区间的字符串表示方法 `String()`。

4. **定义了多种约束类型，用于在值范围分析中表达对变量取值的限制:**
   - `IntArithmeticConstraint`: 表示整数的算术运算约束 (加法、减法、乘法)。包含操作数 `A` 和 `B`，操作符 `Op`，以及一个执行实际区间运算的函数 `Fn`。
   - `IntAddConstraint`, `IntSubConstraint`, `IntMulConstraint`: 分别是加法、减法、乘法约束的具体类型。
   - `IntConversionConstraint`: 表示类型转换约束，包含被转换的值 `X`。
   - `IntIntersectionConstraint`: 表示基于条件判断的区间交集约束。包含参与比较的值 `A` 和 `B`，比较操作符 `Op`，以及在条件成立/不成立时变量可能的区间 `I`。
   - `IntIntervalConstraint`: 表示变量的取值必须在一个给定的区间 `I` 内。

5. **提供了创建各种约束的函数，例如 `NewIntAddConstraint`，`NewIntSubConstraint` 等。**

6. **定义了无穷值的常量 `NInfinity` 和 `PInfinity`，以及空区间 `EmptyIntInterval`。**

7. **提供了根据 SSA (Static Single Assignment) 值推断初始无限区间的函数 `InfinityFor`。**

8. **约束类型实现了 `Constraint` 接口 (代码中未完全展示，但从方法名可以推断)，提供了诸如 `Operands()`, `String()`, `Eval()`, `Futures()`, `Resolve()`, `IsKnown()`, `MarkUnresolved()`, `MarkResolved()`, `IsResolved()` 等方法。**
   - `Operands()`: 返回约束涉及的操作数。
   - `String()`: 返回约束的字符串表示。
   - `Eval()`:  **核心功能**，根据操作数的当前值范围（从 `Graph` 中获取）计算约束变量的值范围。
   - `Futures()`: 返回该约束影响的后续 SSA 值。
   - `Resolve()`:  对于 `IntIntersectionConstraint`，当比较的另一边的值范围确定时，根据比较操作符更新约束变量的区间。
   - `IsKnown()`, `MarkUnresolved()`, `MarkResolved()`, `IsResolved()`: 用于管理约束的解决状态。

**推理 Go 语言功能实现: 值范围分析 (Value Range Analysis / Interval Analysis)**

这段代码是实现值范围分析的核心部分。值范围分析是一种静态分析技术，用于确定程序中变量可能取值的范围。这对于编译优化、错误检测 (例如，数组越界) 非常有用。

**Go 代码示例:**

```go
package main

import (
	"fmt"
	"go/token"

	"honnef.co/go/tools/staticcheck/vrp"
	"honnef.co/go/types/typeutil" // 假设需要这个包来创建类型信息
)

func main() {
	// 创建一些整数值
	z1 := vrp.NewZ(5)
	z2 := vrp.NewZ(10)
	inf := vrp.PInfinity
	negInf := vrp.NInfinity

	fmt.Println("z1:", z1)        // Output: z1: 5
	fmt.Println("z1 + z2:", z1.Add(z2)) // Output: z1 + z2: 15
	fmt.Println("z1 - z2:", z1.Sub(z2)) // Output: z1 - z2: -5
	fmt.Println("z1 * z2:", z1.Mul(z2)) // Output: z1 * z2: 50
	fmt.Println("inf + z1:", inf.Add(z1)) // Output: inf + z1: ∞
	fmt.Println("inf - inf:", inf.Sub(inf)) // Output: inf - inf: runtime error: fmt.Sprintf: %s - %s is not defined, ∞ - ∞

	// 创建一些整数区间
	interval1 := vrp.NewIntInterval(vrp.NewZ(0), vrp.NewZ(10))
	interval2 := vrp.NewIntInterval(vrp.NewZ(5), vrp.NewZ(15))

	fmt.Println("interval1:", interval1) // Output: interval1: [0, 10]
	fmt.Println("interval2:", interval2) // Output: interval2: [5, 15]
	fmt.Println("interval1 交 interval2:", interval1.Intersection(interval2)) // Output: interval1 交 interval2: [5, 10]
	fmt.Println("interval1 并 interval2:", interval1.Union(interval2))       // Output: interval1 并 interval2: [0, 15]
	fmt.Println("interval1 + interval2:", interval1.Add(interval2))         // Output: interval1 + interval2: [5, 25]

	// 模拟一个加法约束 (需要 ssa.Value 类型的操作数，这里简化模拟)
	// 假设 a 和 b 的值范围分别是 interval1 和 interval2
	addResultInterval := interval1.Add(interval2)
	fmt.Println("加法结果区间:", addResultInterval) // Output: 加法结果区间: [5, 25]

	// 模拟一个条件判断约束 (需要 ssa.Value 类型的操作数和比较操作符，这里简化模拟)
	// 假设变量 x 的范围是 interval1，并且有一个条件 x > 5
	greaterThan5Interval := vrp.NewIntInterval(vrp.NewZ(6), vrp.PInfinity) // 大于 5 的区间
	intersection := interval1.Intersection(greaterThan5Interval)
	fmt.Println("interval1 与 x > 5 的交集:", intersection) // Output: interval1 与 x > 5 的交集: [6, 10]

}
```

**假设的输入与输出 (针对 `Eval` 方法):**

假设我们有一个 `IntAddConstraint`，其 `A` 的值范围是 `[0, 5]`，`B` 的值范围是 `[10, 15]`。

**输入:**
- `c`: 一个 `IntAddConstraint` 实例，`c.A` 的范围是 `IntInterval{known: true, Lower: NewZ(0), Upper: NewZ(5)}`，`c.B` 的范围是 `IntInterval{known: true, Lower: NewZ(10), Upper: NewZ(15)}`。
- `g`: 一个 `Graph` 实例 (未在代码中完全展示)，它存储了程序中各个变量的值范围。`g.Range(c.A)` 返回 `[0, 5]`，`g.Range(c.B)` 返回 `[10, 15]`.

**输出:**
- `c.Eval(g)` 将返回一个新的 `IntInterval`: `IntInterval{known: true, Lower: NewZ(10), Upper: NewZ(20)}` (因为 0+10=10, 5+15=20)。

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。它是 `gometalinter` 工具内部的一部分，`gometalinter` 本身会处理命令行参数来指定要分析的代码路径、启用的检查器等。具体的参数处理逻辑在 `gometalinter` 的主程序中。

**使用者易犯错的点 (在使用 `honnef.co/go/tools/staticcheck` 进行代码分析时):**

1. **误解值范围分析的局限性:** 值范围分析是静态分析，它只能在编译时推断变量的可能取值范围。对于动态变化的值 (例如，从用户输入获取的值)，分析结果可能不够精确，可能会得到一个较大的范围。

2. **忽略类型转换可能导致的范围变化:**  在进行类型转换时，值的范围可能会发生变化。例如，将一个有符号整数转换为无符号整数，负数会变成很大的正数。代码中的 `IntConversionConstraint` 试图处理这种情况，但如果代码中存在复杂的类型转换逻辑，分析结果可能不完全准确。

3. **过度依赖精确的范围信息:**  虽然值范围分析可以提供有用的信息，但不应该将其视为绝对真理。例如，即使分析表明一个数组的索引访问在已知范围内，也可能由于其他未分析到的因素导致越界。

4. **不理解无穷值的含义:** 在值范围分析中，无穷值表示可能的取值没有明确的上限或下限。在进行区间运算时，需要特别注意无穷值的处理规则，否则可能会得到意想不到的结果。例如，`PInfinity - PInfinity` 是未定义的。

总而言之，这段代码是 `staticcheck` 工具中用于进行整数类型值范围分析的关键组成部分，它定义了表示整数、整数区间和各种约束的数据结构和方法，用于在静态分析过程中推断变量的取值范围。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/staticcheck/vrp/int.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
package vrp

import (
	"fmt"
	"go/token"
	"go/types"
	"math/big"

	"honnef.co/go/tools/ssa"
)

type Zs []Z

func (zs Zs) Len() int {
	return len(zs)
}

func (zs Zs) Less(i int, j int) bool {
	return zs[i].Cmp(zs[j]) == -1
}

func (zs Zs) Swap(i int, j int) {
	zs[i], zs[j] = zs[j], zs[i]
}

type Z struct {
	infinity int8
	integer  *big.Int
}

func NewZ(n int64) Z {
	return NewBigZ(big.NewInt(n))
}

func NewBigZ(n *big.Int) Z {
	return Z{integer: n}
}

func (z1 Z) Infinite() bool {
	return z1.infinity != 0
}

func (z1 Z) Add(z2 Z) Z {
	if z2.Sign() == -1 {
		return z1.Sub(z2.Negate())
	}
	if z1 == NInfinity {
		return NInfinity
	}
	if z1 == PInfinity {
		return PInfinity
	}
	if z2 == PInfinity {
		return PInfinity
	}

	if !z1.Infinite() && !z2.Infinite() {
		n := &big.Int{}
		n.Add(z1.integer, z2.integer)
		return NewBigZ(n)
	}

	panic(fmt.Sprintf("%s + %s is not defined", z1, z2))
}

func (z1 Z) Sub(z2 Z) Z {
	if z2.Sign() == -1 {
		return z1.Add(z2.Negate())
	}
	if !z1.Infinite() && !z2.Infinite() {
		n := &big.Int{}
		n.Sub(z1.integer, z2.integer)
		return NewBigZ(n)
	}

	if z1 != PInfinity && z2 == PInfinity {
		return NInfinity
	}
	if z1.Infinite() && !z2.Infinite() {
		return Z{infinity: z1.infinity}
	}
	if z1 == PInfinity && z2 == PInfinity {
		return PInfinity
	}
	panic(fmt.Sprintf("%s - %s is not defined", z1, z2))
}

func (z1 Z) Mul(z2 Z) Z {
	if (z1.integer != nil && z1.integer.Sign() == 0) ||
		(z2.integer != nil && z2.integer.Sign() == 0) {
		return NewBigZ(&big.Int{})
	}

	if z1.infinity != 0 || z2.infinity != 0 {
		return Z{infinity: int8(z1.Sign() * z2.Sign())}
	}

	n := &big.Int{}
	n.Mul(z1.integer, z2.integer)
	return NewBigZ(n)
}

func (z1 Z) Negate() Z {
	if z1.infinity == 1 {
		return NInfinity
	}
	if z1.infinity == -1 {
		return PInfinity
	}
	n := &big.Int{}
	n.Neg(z1.integer)
	return NewBigZ(n)
}

func (z1 Z) Sign() int {
	if z1.infinity != 0 {
		return int(z1.infinity)
	}
	return z1.integer.Sign()
}

func (z1 Z) String() string {
	if z1 == NInfinity {
		return "-∞"
	}
	if z1 == PInfinity {
		return "∞"
	}
	return fmt.Sprintf("%d", z1.integer)
}

func (z1 Z) Cmp(z2 Z) int {
	if z1.infinity == z2.infinity && z1.infinity != 0 {
		return 0
	}
	if z1 == PInfinity {
		return 1
	}
	if z1 == NInfinity {
		return -1
	}
	if z2 == NInfinity {
		return 1
	}
	if z2 == PInfinity {
		return -1
	}
	return z1.integer.Cmp(z2.integer)
}

func MaxZ(zs ...Z) Z {
	if len(zs) == 0 {
		panic("Max called with no arguments")
	}
	if len(zs) == 1 {
		return zs[0]
	}
	ret := zs[0]
	for _, z := range zs[1:] {
		if z.Cmp(ret) == 1 {
			ret = z
		}
	}
	return ret
}

func MinZ(zs ...Z) Z {
	if len(zs) == 0 {
		panic("Min called with no arguments")
	}
	if len(zs) == 1 {
		return zs[0]
	}
	ret := zs[0]
	for _, z := range zs[1:] {
		if z.Cmp(ret) == -1 {
			ret = z
		}
	}
	return ret
}

var NInfinity = Z{infinity: -1}
var PInfinity = Z{infinity: 1}
var EmptyIntInterval = IntInterval{true, PInfinity, NInfinity}

func InfinityFor(v ssa.Value) IntInterval {
	if b, ok := v.Type().Underlying().(*types.Basic); ok {
		if (b.Info() & types.IsUnsigned) != 0 {
			return NewIntInterval(NewZ(0), PInfinity)
		}
	}
	return NewIntInterval(NInfinity, PInfinity)
}

type IntInterval struct {
	known bool
	Lower Z
	Upper Z
}

func NewIntInterval(l, u Z) IntInterval {
	if u.Cmp(l) == -1 {
		return EmptyIntInterval
	}
	return IntInterval{known: true, Lower: l, Upper: u}
}

func (i IntInterval) IsKnown() bool {
	return i.known
}

func (i IntInterval) Empty() bool {
	return i.Lower == PInfinity && i.Upper == NInfinity
}

func (i IntInterval) IsMaxRange() bool {
	return i.Lower == NInfinity && i.Upper == PInfinity
}

func (i1 IntInterval) Intersection(i2 IntInterval) IntInterval {
	if !i1.IsKnown() {
		return i2
	}
	if !i2.IsKnown() {
		return i1
	}
	if i1.Empty() || i2.Empty() {
		return EmptyIntInterval
	}
	i3 := NewIntInterval(MaxZ(i1.Lower, i2.Lower), MinZ(i1.Upper, i2.Upper))
	if i3.Lower.Cmp(i3.Upper) == 1 {
		return EmptyIntInterval
	}
	return i3
}

func (i1 IntInterval) Union(other Range) Range {
	i2, ok := other.(IntInterval)
	if !ok {
		i2 = EmptyIntInterval
	}
	if i1.Empty() || !i1.IsKnown() {
		return i2
	}
	if i2.Empty() || !i2.IsKnown() {
		return i1
	}
	return NewIntInterval(MinZ(i1.Lower, i2.Lower), MaxZ(i1.Upper, i2.Upper))
}

func (i1 IntInterval) Add(i2 IntInterval) IntInterval {
	if i1.Empty() || i2.Empty() {
		return EmptyIntInterval
	}
	l1, u1, l2, u2 := i1.Lower, i1.Upper, i2.Lower, i2.Upper
	return NewIntInterval(l1.Add(l2), u1.Add(u2))
}

func (i1 IntInterval) Sub(i2 IntInterval) IntInterval {
	if i1.Empty() || i2.Empty() {
		return EmptyIntInterval
	}
	l1, u1, l2, u2 := i1.Lower, i1.Upper, i2.Lower, i2.Upper
	return NewIntInterval(l1.Sub(u2), u1.Sub(l2))
}

func (i1 IntInterval) Mul(i2 IntInterval) IntInterval {
	if i1.Empty() || i2.Empty() {
		return EmptyIntInterval
	}
	x1, x2 := i1.Lower, i1.Upper
	y1, y2 := i2.Lower, i2.Upper
	return NewIntInterval(
		MinZ(x1.Mul(y1), x1.Mul(y2), x2.Mul(y1), x2.Mul(y2)),
		MaxZ(x1.Mul(y1), x1.Mul(y2), x2.Mul(y1), x2.Mul(y2)),
	)
}

func (i1 IntInterval) String() string {
	if !i1.IsKnown() {
		return "[⊥, ⊥]"
	}
	if i1.Empty() {
		return "{}"
	}
	return fmt.Sprintf("[%s, %s]", i1.Lower, i1.Upper)
}

type IntArithmeticConstraint struct {
	aConstraint
	A  ssa.Value
	B  ssa.Value
	Op token.Token
	Fn func(IntInterval, IntInterval) IntInterval
}

type IntAddConstraint struct{ *IntArithmeticConstraint }
type IntSubConstraint struct{ *IntArithmeticConstraint }
type IntMulConstraint struct{ *IntArithmeticConstraint }

type IntConversionConstraint struct {
	aConstraint
	X ssa.Value
}

type IntIntersectionConstraint struct {
	aConstraint
	ranges   Ranges
	A        ssa.Value
	B        ssa.Value
	Op       token.Token
	I        IntInterval
	resolved bool
}

type IntIntervalConstraint struct {
	aConstraint
	I IntInterval
}

func NewIntArithmeticConstraint(a, b, y ssa.Value, op token.Token, fn func(IntInterval, IntInterval) IntInterval) *IntArithmeticConstraint {
	return &IntArithmeticConstraint{NewConstraint(y), a, b, op, fn}
}
func NewIntAddConstraint(a, b, y ssa.Value) Constraint {
	return &IntAddConstraint{NewIntArithmeticConstraint(a, b, y, token.ADD, IntInterval.Add)}
}
func NewIntSubConstraint(a, b, y ssa.Value) Constraint {
	return &IntSubConstraint{NewIntArithmeticConstraint(a, b, y, token.SUB, IntInterval.Sub)}
}
func NewIntMulConstraint(a, b, y ssa.Value) Constraint {
	return &IntMulConstraint{NewIntArithmeticConstraint(a, b, y, token.MUL, IntInterval.Mul)}
}
func NewIntConversionConstraint(x, y ssa.Value) Constraint {
	return &IntConversionConstraint{NewConstraint(y), x}
}
func NewIntIntersectionConstraint(a, b ssa.Value, op token.Token, ranges Ranges, y ssa.Value) Constraint {
	return &IntIntersectionConstraint{
		aConstraint: NewConstraint(y),
		ranges:      ranges,
		A:           a,
		B:           b,
		Op:          op,
	}
}
func NewIntIntervalConstraint(i IntInterval, y ssa.Value) Constraint {
	return &IntIntervalConstraint{NewConstraint(y), i}
}

func (c *IntArithmeticConstraint) Operands() []ssa.Value   { return []ssa.Value{c.A, c.B} }
func (c *IntConversionConstraint) Operands() []ssa.Value   { return []ssa.Value{c.X} }
func (c *IntIntersectionConstraint) Operands() []ssa.Value { return []ssa.Value{c.A} }
func (s *IntIntervalConstraint) Operands() []ssa.Value     { return nil }

func (c *IntArithmeticConstraint) String() string {
	return fmt.Sprintf("%s = %s %s %s", c.Y().Name(), c.A.Name(), c.Op, c.B.Name())
}
func (c *IntConversionConstraint) String() string {
	return fmt.Sprintf("%s = %s(%s)", c.Y().Name(), c.Y().Type(), c.X.Name())
}
func (c *IntIntersectionConstraint) String() string {
	return fmt.Sprintf("%s = %s %s %s (%t branch)", c.Y().Name(), c.A.Name(), c.Op, c.B.Name(), c.Y().(*ssa.Sigma).Branch)
}
func (c *IntIntervalConstraint) String() string { return fmt.Sprintf("%s = %s", c.Y().Name(), c.I) }

func (c *IntArithmeticConstraint) Eval(g *Graph) Range {
	i1, i2 := g.Range(c.A).(IntInterval), g.Range(c.B).(IntInterval)
	if !i1.IsKnown() || !i2.IsKnown() {
		return IntInterval{}
	}
	return c.Fn(i1, i2)
}
func (c *IntConversionConstraint) Eval(g *Graph) Range {
	s := &types.StdSizes{
		// XXX is it okay to assume the largest word size, or do we
		// need to be platform specific?
		WordSize: 8,
		MaxAlign: 1,
	}
	fromI := g.Range(c.X).(IntInterval)
	toI := g.Range(c.Y()).(IntInterval)
	fromT := c.X.Type().Underlying().(*types.Basic)
	toT := c.Y().Type().Underlying().(*types.Basic)
	fromB := s.Sizeof(c.X.Type())
	toB := s.Sizeof(c.Y().Type())

	if !fromI.IsKnown() {
		return toI
	}
	if !toI.IsKnown() {
		return fromI
	}

	// uint<N> -> sint/uint<M>, M > N: [max(0, l1), min(2**N-1, u2)]
	if (fromT.Info()&types.IsUnsigned != 0) &&
		toB > fromB {

		n := big.NewInt(1)
		n.Lsh(n, uint(fromB*8))
		n.Sub(n, big.NewInt(1))
		return NewIntInterval(
			MaxZ(NewZ(0), fromI.Lower),
			MinZ(NewBigZ(n), toI.Upper),
		)
	}

	// sint<N> -> sint<M>, M > N; [max(-∞, l1), min(2**N-1, u2)]
	if (fromT.Info()&types.IsUnsigned == 0) &&
		(toT.Info()&types.IsUnsigned == 0) &&
		toB > fromB {

		n := big.NewInt(1)
		n.Lsh(n, uint(fromB*8))
		n.Sub(n, big.NewInt(1))
		return NewIntInterval(
			MaxZ(NInfinity, fromI.Lower),
			MinZ(NewBigZ(n), toI.Upper),
		)
	}

	return fromI
}
func (c *IntIntersectionConstraint) Eval(g *Graph) Range {
	xi := g.Range(c.A).(IntInterval)
	if !xi.IsKnown() {
		return c.I
	}
	return xi.Intersection(c.I)
}
func (c *IntIntervalConstraint) Eval(*Graph) Range { return c.I }

func (c *IntIntersectionConstraint) Futures() []ssa.Value {
	return []ssa.Value{c.B}
}

func (c *IntIntersectionConstraint) Resolve() {
	r, ok := c.ranges[c.B].(IntInterval)
	if !ok {
		c.I = InfinityFor(c.Y())
		return
	}

	switch c.Op {
	case token.EQL:
		c.I = r
	case token.GTR:
		c.I = NewIntInterval(r.Lower.Add(NewZ(1)), PInfinity)
	case token.GEQ:
		c.I = NewIntInterval(r.Lower, PInfinity)
	case token.LSS:
		// TODO(dh): do we need 0 instead of NInfinity for uints?
		c.I = NewIntInterval(NInfinity, r.Upper.Sub(NewZ(1)))
	case token.LEQ:
		c.I = NewIntInterval(NInfinity, r.Upper)
	case token.NEQ:
		c.I = InfinityFor(c.Y())
	default:
		panic("unsupported op " + c.Op.String())
	}
}

func (c *IntIntersectionConstraint) IsKnown() bool {
	return c.I.IsKnown()
}

func (c *IntIntersectionConstraint) MarkUnresolved() {
	c.resolved = false
}

func (c *IntIntersectionConstraint) MarkResolved() {
	c.resolved = true
}

func (c *IntIntersectionConstraint) IsResolved() bool {
	return c.resolved
}

"""



```