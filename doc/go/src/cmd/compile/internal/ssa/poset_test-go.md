Response: Let's break down the thought process for analyzing this Go test file.

**1. Initial Understanding - Context is Key:**

The first step is recognizing this file's location: `go/src/cmd/compile/internal/ssa/poset_test.go`. This immediately tells us:

* **`go/src`:**  This is part of the Go standard library's source code.
* **`cmd/compile`:** This relates to the Go compiler.
* **`internal/ssa`:**  This is within the compiler and deals with Static Single Assignment (SSA) form, a crucial intermediate representation for optimization.
* **`poset_test.go`:** This is a test file for something called "poset."

Therefore, the core function of this code is to *test the implementation of a partially ordered set (poset) data structure used within the Go compiler's SSA framework*.

**2. Identifying Core Components:**

Next, scan the file for key elements:

* **Constants:** The `const` block defines various string constants like `SetOrder`, `Ordered`, `Equal`, etc., along with their "_Fail" counterparts. These clearly represent operations or assertions related to the poset's behavior. The "_Fail" suggests testing for expected failures.
* **`posetTestOp` struct:** This struct, containing `typ`, `a`, and `b`, is used to define test operations. `typ` refers to the constants defined earlier, and `a` and `b` are likely indices referring to elements within the poset.
* **`vconst` function:** This function creates "constant" values for testing. The hardcoded range (`-128` to `127`) and the offset (`1000 + 128`) are implementation details, but the purpose is clear.
* **`testPosetOps` function:** This is the main test runner. It takes a `testing.T`, a boolean for unsignedness, and a slice of `posetTestOp`. This function orchestrates the tests by iterating through the operations and calling methods on a `poset` instance.
* **`TestPoset` and `TestPosetStrict`, `TestPosetCollapse`, `TestPosetSetEqual`, `TestPosetNonEqual` functions:** These are the actual test functions called by `go test`. They each define a series of `posetTestOp` to test specific scenarios.

**3. Inferring Functionality (The Poset's Purpose):**

Based on the constants and the operations within `testPosetOps`, we can infer the poset's core functions:

* **Ordering:** `SetOrder`, `Ordered`, `SetOrderOrEqual`, `OrderedOrEqual`. This strongly suggests the poset is used to represent ordering relationships between elements.
* **Equality:** `SetEqual`, `Equal`, `SetNonEqual`, `NonEqual`. The poset likely tracks equality and inequality relationships.
* **State Management:** `Checkpoint`, `Undo`. This indicates the poset supports saving and reverting to previous states, essential for backtracking or exploring different optimization paths in the compiler.
* **Unsignedness:** The `unsigned` parameter in `testPosetOps` suggests the poset can handle comparisons for both signed and unsigned values.

**4. Code Example Construction (Illustrating the Poset's Use):**

Now, try to imagine how this poset might be used within the compiler. A common use case for ordering in compilers is comparing values or expressions. The code example focuses on comparing `Value` objects, which are fundamental in SSA.

* **Hypothesize Input:** Two `Value` objects, perhaps representing the results of calculations.
* **Core Poset Operations:**  Use `SetOrder` to establish an ordering and `Ordered` to check the established order.
* **Illustrate Failure:** Show how `Ordered` fails when the order isn't established.
* **Illustrate Equality:**  Use `SetEqual` and `Equal`.
* **Illustrate Non-Equality:** Use `SetNonEqual` and `NonEqual`.

**5. Inferring Go Feature Implementation (Connecting to Compiler Concepts):**

The poset's functionality directly relates to compiler optimizations:

* **Value Numbering:**  The equality operations (`SetEqual`, `Equal`) are likely used in value numbering, where the compiler tries to identify and reuse computations with the same value.
* **Range Analysis/Comparison:** The ordering operations (`SetOrder`, `Ordered`, etc.) can be used for range analysis or to determine if one value is definitely less than, greater than, or equal to another. This information is vital for conditional branch optimization and other transformations.

**6. Command-Line Arguments (Looking for Context):**

Since this is a test file, the primary command-line interaction is through `go test`. While the *test file itself* doesn't directly process specific arguments beyond the standard `go test` flags, the *poset implementation* within the compiler might be influenced by compiler flags related to optimization levels or specific optimization passes. However, this test focuses on the core logic of the poset, independent of those higher-level flags.

**7. Common Mistakes (Thinking Like a User/Developer):**

Consider how a developer using this `poset` within the compiler might make errors:

* **Assuming Transitivity of Inequality:**  The test case for `SetNonEqual` highlights that inequality is *not* transitive. A common mistake is to assume that if `A != B` and `B != C`, then `A != C`. The poset correctly enforces this.
* **Incorrectly Using `SetOrder` vs. `SetOrderOrEqual`:**  Forgetting the difference between strict and non-strict ordering can lead to unexpected behavior.
* **Not Understanding Checkpoint/Undo:**  Improperly using the checkpoint and undo mechanisms can lead to incorrect state management.

**8. Review and Refine:**

Finally, review the entire analysis, ensuring that the explanations are clear, concise, and directly related to the provided code snippet. Double-check the code examples for correctness and clarity.

This systematic approach helps in understanding the purpose and functionality of the given Go test code and its relation to the broader context of the Go compiler.
这是 `go/src/cmd/compile/internal/ssa/poset_test.go` 文件的一部分，它主要用于测试 `ssa` 包中 `poset` 类型的实现。 `poset` 是一个部分有序集合（Partially Ordered Set）的数据结构。

**功能列表:**

1. **定义测试操作:**  定义了一系列用于测试 `poset` 功能的操作类型，如 `SetOrder` (设置顺序关系), `Ordered` (检查是否已排序), `SetEqual` (设置相等关系), `Equal` (检查是否相等), `SetNonEqual` (设置不等关系), `NonEqual` (检查是否不等), `Checkpoint` (创建检查点), `Undo` (回滚到上一个检查点)。

2. **定义测试操作结构体:** `posetTestOp` 结构体用于表示一个测试操作，包含操作类型 (`typ`) 和操作涉及的两个元素的索引 (`a`, `b`).

3. **创建用于测试的值:** `vconst` 函数用于创建具有特定 `Op` 和 `AuxInt` 的 `Value` 对象，模拟 SSA 中的常量值。这有助于在测试中模拟真实的编译器场景。

4. **核心测试函数:** `testPosetOps` 是核心的测试执行函数。它接收一个 `testing.T` 对象，一个表示是否使用无符号比较的布尔值，以及一个 `posetTestOp` 类型的操作序列。它会创建一个 `poset` 实例，然后按顺序执行操作序列，并使用 `t.Errorf` 来断言操作的结果是否符合预期。

5. **具体的测试用例:** `TestPoset`, `TestPosetStrict`, `TestPosetCollapse`, `TestPosetSetEqual`, `TestPosetNonEqual` 这些函数是具体的测试用例，每个用例都定义了一系列 `posetTestOp` 操作来测试 `poset` 的不同方面和场景。

**`poset` 是什么 Go 语言功能的实现（推断）:**

基于测试代码中的操作，可以推断 `poset` 是用来维护 SSA 中 `Value` 之间的关系，特别是关于它们的值的顺序和相等性。这在编译器的优化阶段非常重要，例如：

* **值编号 (Value Numbering):**  `SetEqual` 和 `Equal` 操作可能用于判断两个 `Value` 是否具有相同的值，从而进行公共子表达式消除等优化。
* **条件分支优化:** `SetOrder`, `Ordered`, `SetOrderOrEqual`, `OrderedOrEqual` 操作可能用于推断 `Value` 之间的比较关系，从而简化或消除不必要的条件分支。
* **常量折叠:**  通过维护常量之间的关系，可以进行常量折叠优化。

**Go 代码示例说明:**

假设 `poset` 用于跟踪 SSA 中两个 `Value` 对象 `v1` 和 `v2` 的关系。

```go
package main

import (
	"fmt"
	"testing"
)

// 假设的 Value 和 Poset 定义 (简化版)
type Value struct {
	ID     int
	AuxInt int64
}

type Poset struct {
	// ... 内部结构用于维护顺序和相等关系 ...
}

func NewPoset() *Poset {
	return &Poset{}
}

func (p *Poset) SetOrder(a, b *Value) bool {
	// ... 实现设置 a < b 的逻辑 ...
	fmt.Printf("SetOrder(%d, %d)\n", a.ID, b.ID)
	return true
}

func (p *Poset) Ordered(a, b *Value) bool {
	// ... 实现检查是否 a < b 的逻辑 ...
	fmt.Printf("Ordered(%d, %d)\n", a.ID, b.ID)
	return true
}

func main() {
	v1 := &Value{ID: 1, AuxInt: 10}
	v2 := &Value{ID: 2, AuxInt: 20}

	po := NewPoset()

	// 设置 v1 < v2 的关系
	po.SetOrder(v1, v2)

	// 检查 v1 是否小于 v2
	if po.Ordered(v1, v2) {
		fmt.Println("v1 is ordered before v2")
	} else {
		fmt.Println("v1 is not ordered before v2")
	}
}
```

**假设的输入与输出:**

在 `testPosetOps` 函数中，输入是 `ops []posetTestOp`，它定义了要执行的操作序列。例如，对于以下操作：

```go
[]posetTestOp{
    {SetOrder, 100, 101}, // 设置 v[100] < v[101]
    {Ordered, 100, 101},  // 检查 v[100] 是否小于 v[101]
    {Ordered_Fail, 101, 100}, // 检查 v[101] 是否小于 v[100]，期望失败
}
```

* **假设的输入:**  `v[100]` 和 `v[101]` 是两个 `Value` 对象，它们可能代表 SSA 中的不同操作结果。
* **期望的输出:**
    * `SetOrder(v[100], v[101])` 应该成功设置顺序关系。
    * `Ordered(v[100], v[101])` 应该返回 `true`。
    * `Ordered_Fail(v[101], v[100])` 应该返回 `false`，如果返回 `true`，则 `t.Errorf` 会报告失败。

**命令行参数的具体处理:**

这个测试文件本身并不直接处理命令行参数。它是一个标准的 Go 测试文件，通过 `go test` 命令来运行。`go test` 命令有一些标准的参数，例如：

* `-v`:  显示更详细的测试输出。
* `-run <pattern>`:  只运行匹配指定模式的测试用例。

例如，要只运行 `TestPoset` 测试用例，可以使用命令：

```bash
go test -v -run TestPoset go/src/cmd/compile/internal/ssa
```

**使用者易犯错的点:**

从测试代码中可以看出，使用 `poset` 时容易犯错的点包括：

1. **混淆严格顺序和非严格顺序:**  `SetOrder` 设置严格的小于关系 (`<`)，而 `SetOrderOrEqual` 设置小于等于关系 (`<=`). 错误地使用这两个操作可能导致逻辑错误。例如，如果已经设置了 `a < b`，再尝试设置 `b <= a` 应该会失败。

   ```go
   // 错误示例
   ops := []posetTestOp{
       {SetOrder, 100, 101}, // v[100] < v[101]
       {SetOrderOrEqual, 101, 100}, // 尝试设置 v[101] <= v[100]，这应该会导致错误
   }
   ```

2. **假设不等关系的传递性:**  `SetNonEqual` 设置两个元素不相等，但这并不意味着不等关系是传递的。如果 `a != b` 和 `b != c`，并不能推断出 `a != c`。测试用例中对此有明确的验证。

   ```go
   // 错误示例 - 假设不等关系传递
   ops := []posetTestOp{
       {SetNonEqual, 100, 101},
       {SetNonEqual, 101, 102},
       {NonEqual, 100, 102}, // 错误地认为这里会成功
   }
   ```

3. **不理解 `Checkpoint` 和 `Undo` 的作用域:** `Checkpoint` 会保存当前状态，`Undo` 会回滚到上一个检查点。如果在没有 `Checkpoint` 的情况下调用 `Undo`，或者错误地期望 `Undo` 回滚到更早的状态，可能会导致意外的结果。

   ```go
   // 错误示例 - 错误地使用 Undo
   ops := []posetTestOp{
       {SetOrder, 100, 101},
       {Checkpoint, 0, 0},
       {SetOrder, 101, 102},
       {Undo, 0, 0}, // 回滚到 SetOrder 100, 101 之后的状态
       {Ordered, 101, 102}, // 错误地期望这个操作仍然存在
   }
   ```

总而言之，这个测试文件全面地测试了 `ssa` 包中 `poset` 类型的各种功能，确保它能够正确地维护 SSA 中 `Value` 之间的顺序和相等性关系，这对于编译器的优化至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/poset_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package ssa

import (
	"fmt"
	"testing"
)

const (
	SetOrder             = "SetOrder"
	SetOrder_Fail        = "SetOrder_Fail"
	SetOrderOrEqual      = "SetOrderOrEqual"
	SetOrderOrEqual_Fail = "SetOrderOrEqual_Fail"
	Ordered              = "Ordered"
	Ordered_Fail         = "Ordered_Fail"
	OrderedOrEqual       = "OrderedOrEqual"
	OrderedOrEqual_Fail  = "OrderedOrEqual_Fail"
	SetEqual             = "SetEqual"
	SetEqual_Fail        = "SetEqual_Fail"
	Equal                = "Equal"
	Equal_Fail           = "Equal_Fail"
	SetNonEqual          = "SetNonEqual"
	SetNonEqual_Fail     = "SetNonEqual_Fail"
	NonEqual             = "NonEqual"
	NonEqual_Fail        = "NonEqual_Fail"
	Checkpoint           = "Checkpoint"
	Undo                 = "Undo"
)

type posetTestOp struct {
	typ  string
	a, b int
}

func vconst(i int) int {
	if i < -128 || i >= 128 {
		panic("invalid const")
	}
	return 1000 + 128 + i
}

func testPosetOps(t *testing.T, unsigned bool, ops []posetTestOp) {
	var v [1512]*Value
	for i := range v {
		v[i] = new(Value)
		v[i].ID = ID(i)
		if i >= 1000 && i < 1256 {
			v[i].Op = OpConst64
			v[i].AuxInt = int64(i - 1000 - 128)
		}
	}

	po := newPoset()
	po.SetUnsigned(unsigned)
	for idx, op := range ops {
		t.Logf("op%d%v", idx, op)
		switch op.typ {
		case SetOrder:
			if !po.SetOrder(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v failed", idx, op)
			}
		case SetOrder_Fail:
			if po.SetOrder(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v passed", idx, op)
			}
		case SetOrderOrEqual:
			if !po.SetOrderOrEqual(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v failed", idx, op)
			}
		case SetOrderOrEqual_Fail:
			if po.SetOrderOrEqual(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v passed", idx, op)
			}
		case Ordered:
			if !po.Ordered(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v failed", idx, op)
			}
		case Ordered_Fail:
			if po.Ordered(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v passed", idx, op)
			}
		case OrderedOrEqual:
			if !po.OrderedOrEqual(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v failed", idx, op)
			}
		case OrderedOrEqual_Fail:
			if po.OrderedOrEqual(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v passed", idx, op)
			}
		case SetEqual:
			if !po.SetEqual(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v failed", idx, op)
			}
		case SetEqual_Fail:
			if po.SetEqual(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v passed", idx, op)
			}
		case Equal:
			if !po.Equal(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v failed", idx, op)
			}
		case Equal_Fail:
			if po.Equal(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v passed", idx, op)
			}
		case SetNonEqual:
			if !po.SetNonEqual(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v failed", idx, op)
			}
		case SetNonEqual_Fail:
			if po.SetNonEqual(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v passed", idx, op)
			}
		case NonEqual:
			if !po.NonEqual(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v failed", idx, op)
			}
		case NonEqual_Fail:
			if po.NonEqual(v[op.a], v[op.b]) {
				t.Errorf("FAILED: op%d%v passed", idx, op)
			}
		case Checkpoint:
			po.Checkpoint()
		case Undo:
			t.Log("Undo stack", po.undo)
			po.Undo()
		default:
			panic("unimplemented")
		}

		if false {
			po.DotDump(fmt.Sprintf("op%d.dot", idx), fmt.Sprintf("Last op: %v", op))
		}

		po.CheckIntegrity()
	}

	// Check that the poset is completely empty
	if err := po.CheckEmpty(); err != nil {
		t.Error(err)
	}
}

func TestPoset(t *testing.T) {
	testPosetOps(t, false, []posetTestOp{
		{Ordered_Fail, 123, 124},

		// Dag #0: 100<101
		{Checkpoint, 0, 0},
		{SetOrder, 100, 101},
		{Ordered, 100, 101},
		{Ordered_Fail, 101, 100},
		{SetOrder_Fail, 101, 100},
		{SetOrder, 100, 101}, // repeat
		{NonEqual, 100, 101},
		{NonEqual, 101, 100},
		{SetEqual_Fail, 100, 101},

		// Dag #1: 4<=7<12
		{Checkpoint, 0, 0},
		{SetOrderOrEqual, 4, 7},
		{OrderedOrEqual, 4, 7},
		{SetOrder, 7, 12},
		{Ordered, 7, 12},
		{Ordered, 4, 12},
		{Ordered_Fail, 12, 4},
		{NonEqual, 4, 12},
		{NonEqual, 12, 4},
		{NonEqual_Fail, 4, 100},
		{OrderedOrEqual, 4, 12},
		{OrderedOrEqual_Fail, 12, 4},
		{OrderedOrEqual, 4, 7},
		{OrderedOrEqual_Fail, 7, 4},

		// Dag #1: 1<4<=7<12
		{Checkpoint, 0, 0},
		{SetOrder, 1, 4},
		{Ordered, 1, 4},
		{Ordered, 1, 12},
		{Ordered_Fail, 12, 1},

		// Dag #1: 1<4<=7<12, 6<7
		{Checkpoint, 0, 0},
		{SetOrder, 6, 7},
		{Ordered, 6, 7},
		{Ordered, 6, 12},
		{SetOrder_Fail, 7, 4},
		{SetOrder_Fail, 7, 6},
		{SetOrder_Fail, 7, 1},

		// Dag #1: 1<4<=7<12, 1<6<7
		{Checkpoint, 0, 0},
		{Ordered_Fail, 1, 6},
		{SetOrder, 1, 6},
		{Ordered, 1, 6},
		{SetOrder_Fail, 6, 1},

		// Dag #1: 1<4<=7<12, 1<4<6<7
		{Checkpoint, 0, 0},
		{Ordered_Fail, 4, 6},
		{Ordered_Fail, 4, 7},
		{SetOrder, 4, 6},
		{Ordered, 4, 6},
		{OrderedOrEqual, 4, 6},
		{Ordered, 4, 7},
		{OrderedOrEqual, 4, 7},
		{SetOrder_Fail, 6, 4},
		{Ordered_Fail, 7, 6},
		{Ordered_Fail, 7, 4},
		{OrderedOrEqual_Fail, 7, 6},
		{OrderedOrEqual_Fail, 7, 4},

		// Merge: 1<4<6, 4<=7<12, 6<101
		{Checkpoint, 0, 0},
		{Ordered_Fail, 6, 101},
		{SetOrder, 6, 101},
		{Ordered, 6, 101},
		{Ordered, 1, 101},

		// Merge: 1<4<6, 4<=7<12, 6<100<101
		{Checkpoint, 0, 0},
		{Ordered_Fail, 6, 100},
		{SetOrder, 6, 100},
		{Ordered, 1, 100},

		// Undo: 1<4<6<7<12, 6<101
		{Ordered, 100, 101},
		{Undo, 0, 0},
		{Ordered, 100, 101},
		{Ordered_Fail, 6, 100},
		{Ordered, 6, 101},
		{Ordered, 1, 101},

		// Undo: 1<4<6<7<12, 100<101
		{Undo, 0, 0},
		{Ordered_Fail, 1, 100},
		{Ordered_Fail, 1, 101},
		{Ordered_Fail, 6, 100},
		{Ordered_Fail, 6, 101},

		// Merge: 1<4<6<7<12, 6<100<101
		{Checkpoint, 0, 0},
		{Ordered, 100, 101},
		{SetOrder, 6, 100},
		{Ordered, 6, 100},
		{Ordered, 6, 101},
		{Ordered, 1, 101},

		// Undo 2 times: 1<4<7<12, 1<6<7
		{Undo, 0, 0},
		{Undo, 0, 0},
		{Ordered, 1, 6},
		{Ordered, 4, 12},
		{Ordered_Fail, 4, 6},
		{SetOrder_Fail, 6, 1},

		// Undo 2 times: 1<4<7<12
		{Undo, 0, 0},
		{Undo, 0, 0},
		{Ordered, 1, 12},
		{Ordered, 7, 12},
		{Ordered_Fail, 1, 6},
		{Ordered_Fail, 6, 7},
		{Ordered, 100, 101},
		{Ordered_Fail, 1, 101},

		// Undo: 4<7<12
		{Undo, 0, 0},
		{Ordered_Fail, 1, 12},
		{Ordered_Fail, 1, 4},
		{Ordered, 4, 12},
		{Ordered, 100, 101},

		// Undo: 100<101
		{Undo, 0, 0},
		{Ordered_Fail, 4, 7},
		{Ordered_Fail, 7, 12},
		{Ordered, 100, 101},

		// Recreated DAG #1 from scratch, reusing same nodes.
		// This also stresses that Undo has done its job correctly.
		// DAG: 1<2<(5|6), 101<102<(105|106<107)
		{Checkpoint, 0, 0},
		{SetOrder, 101, 102},
		{SetOrder, 102, 105},
		{SetOrder, 102, 106},
		{SetOrder, 106, 107},
		{SetOrder, 1, 2},
		{SetOrder, 2, 5},
		{SetOrder, 2, 6},
		{SetEqual_Fail, 1, 6},
		{SetEqual_Fail, 107, 102},

		// Now Set 2 == 102
		// New DAG: (1|101)<2==102<(5|6|105|106<107)
		{Checkpoint, 0, 0},
		{SetEqual, 2, 102},
		{Equal, 2, 102},
		{SetEqual, 2, 102},         // trivially pass
		{SetNonEqual_Fail, 2, 102}, // trivially fail
		{Ordered, 1, 107},
		{Ordered, 101, 6},
		{Ordered, 101, 105},
		{Ordered, 2, 106},
		{Ordered, 102, 6},

		// Undo SetEqual
		{Undo, 0, 0},
		{Equal_Fail, 2, 102},
		{Ordered_Fail, 2, 102},
		{Ordered_Fail, 1, 107},
		{Ordered_Fail, 101, 6},
		{Checkpoint, 0, 0},
		{SetEqual, 2, 100},
		{Ordered, 1, 107},
		{Ordered, 100, 6},

		// SetEqual with new node
		{Undo, 0, 0},
		{Checkpoint, 0, 0},
		{SetEqual, 2, 400},
		{SetEqual, 401, 2},
		{Equal, 400, 401},
		{Ordered, 1, 400},
		{Ordered, 400, 6},
		{Ordered, 1, 401},
		{Ordered, 401, 6},
		{Ordered_Fail, 2, 401},

		// SetEqual unseen nodes and then connect
		{Checkpoint, 0, 0},
		{SetEqual, 500, 501},
		{SetEqual, 102, 501},
		{Equal, 500, 102},
		{Ordered, 501, 106},
		{Ordered, 100, 500},
		{SetEqual, 500, 501},
		{Ordered_Fail, 500, 501},
		{Ordered_Fail, 102, 501},

		// SetNonEqual relations
		{Undo, 0, 0},
		{Checkpoint, 0, 0},
		{SetNonEqual, 600, 601},
		{NonEqual, 600, 601},
		{SetNonEqual, 601, 602},
		{NonEqual, 601, 602},
		{NonEqual_Fail, 600, 602}, // non-transitive
		{SetEqual_Fail, 601, 602},

		// Undo back to beginning, leave the poset empty
		{Undo, 0, 0},
		{Undo, 0, 0},
		{Undo, 0, 0},
		{Undo, 0, 0},
	})
}

func TestPosetStrict(t *testing.T) {

	testPosetOps(t, false, []posetTestOp{
		{Checkpoint, 0, 0},
		// Build: 20!=30, 10<20<=30<40. The 20<=30 will become 20<30.
		{SetNonEqual, 20, 30},
		{SetOrder, 10, 20},
		{SetOrderOrEqual, 20, 30}, // this is affected by 20!=30
		{SetOrder, 30, 40},

		{Ordered, 10, 30},
		{Ordered, 20, 30},
		{Ordered, 10, 40},
		{OrderedOrEqual, 10, 30},
		{OrderedOrEqual, 20, 30},
		{OrderedOrEqual, 10, 40},

		{Undo, 0, 0},

		// Now do the opposite: first build the DAG and then learn non-equality
		{Checkpoint, 0, 0},
		{SetOrder, 10, 20},
		{SetOrderOrEqual, 20, 30}, // this is affected by 20!=30
		{SetOrder, 30, 40},

		{Ordered, 10, 30},
		{Ordered_Fail, 20, 30},
		{Ordered, 10, 40},
		{OrderedOrEqual, 10, 30},
		{OrderedOrEqual, 20, 30},
		{OrderedOrEqual, 10, 40},

		{Checkpoint, 0, 0},
		{SetNonEqual, 20, 30},
		{Ordered, 10, 30},
		{Ordered, 20, 30},
		{Ordered, 10, 40},
		{OrderedOrEqual, 10, 30},
		{OrderedOrEqual, 20, 30},
		{OrderedOrEqual, 10, 40},
		{Undo, 0, 0},

		{Checkpoint, 0, 0},
		{SetOrderOrEqual, 30, 35},
		{OrderedOrEqual, 20, 35},
		{Ordered_Fail, 20, 35},
		{SetNonEqual, 20, 35},
		{Ordered, 20, 35},
		{Undo, 0, 0},

		// Learn <= and >=
		{Checkpoint, 0, 0},
		{SetOrderOrEqual, 50, 60},
		{SetOrderOrEqual, 60, 50},
		{OrderedOrEqual, 50, 60},
		{OrderedOrEqual, 60, 50},
		{Ordered_Fail, 50, 60},
		{Ordered_Fail, 60, 50},
		{Equal, 50, 60},
		{Equal, 60, 50},
		{NonEqual_Fail, 50, 60},
		{NonEqual_Fail, 60, 50},
		{Undo, 0, 0},

		{Undo, 0, 0},
	})
}

func TestPosetCollapse(t *testing.T) {
	testPosetOps(t, false, []posetTestOp{
		{Checkpoint, 0, 0},
		// Create a complex graph of <= relations among nodes between 10 and 25.
		{SetOrderOrEqual, 10, 15},
		{SetOrderOrEqual, 15, 20},
		{SetOrderOrEqual, 20, vconst(20)},
		{SetOrderOrEqual, vconst(20), 25},
		{SetOrderOrEqual, 10, 12},
		{SetOrderOrEqual, 12, 16},
		{SetOrderOrEqual, 16, vconst(20)},
		{SetOrderOrEqual, 10, 17},
		{SetOrderOrEqual, 17, 25},
		{SetOrderOrEqual, 15, 18},
		{SetOrderOrEqual, 18, vconst(20)},
		{SetOrderOrEqual, 15, 19},
		{SetOrderOrEqual, 19, 25},

		// These are other paths not part of the main collapsing path
		{SetOrderOrEqual, 10, 11},
		{SetOrderOrEqual, 11, 26},
		{SetOrderOrEqual, 13, 25},
		{SetOrderOrEqual, 100, 25},
		{SetOrderOrEqual, 101, 15},
		{SetOrderOrEqual, 102, 10},
		{SetOrderOrEqual, 25, 103},
		{SetOrderOrEqual, 20, 104},

		{Checkpoint, 0, 0},
		// Collapse everything by setting 10 >= 25: this should make everything equal
		{SetOrderOrEqual, 25, 10},

		// Check that all nodes are pairwise equal now
		{Equal, 10, 12},
		{Equal, 10, 15},
		{Equal, 10, 16},
		{Equal, 10, 17},
		{Equal, 10, 18},
		{Equal, 10, 19},
		{Equal, 10, vconst(20)},
		{Equal, 10, 25},

		{Equal, 12, 15},
		{Equal, 12, 16},
		{Equal, 12, 17},
		{Equal, 12, 18},
		{Equal, 12, 19},
		{Equal, 12, vconst(20)},
		{Equal, 12, 25},

		{Equal, 15, 16},
		{Equal, 15, 17},
		{Equal, 15, 18},
		{Equal, 15, 19},
		{Equal, 15, vconst(20)},
		{Equal, 15, 25},

		{Equal, 16, 17},
		{Equal, 16, 18},
		{Equal, 16, 19},
		{Equal, 16, vconst(20)},
		{Equal, 16, 25},

		{Equal, 17, 18},
		{Equal, 17, 19},
		{Equal, 17, vconst(20)},
		{Equal, 17, 25},

		{Equal, 18, 19},
		{Equal, 18, vconst(20)},
		{Equal, 18, 25},

		{Equal, 19, vconst(20)},
		{Equal, 19, 25},

		{Equal, vconst(20), 25},

		// ... but not 11/26/100/101/102, which were on a different path
		{Equal_Fail, 10, 11},
		{Equal_Fail, 10, 26},
		{Equal_Fail, 10, 100},
		{Equal_Fail, 10, 101},
		{Equal_Fail, 10, 102},
		{OrderedOrEqual, 10, 26},
		{OrderedOrEqual, 25, 26},
		{OrderedOrEqual, 13, 25},
		{OrderedOrEqual, 13, 10},

		{Undo, 0, 0},
		{OrderedOrEqual, 10, 25},
		{Equal_Fail, 10, 12},
		{Equal_Fail, 10, 15},
		{Equal_Fail, 10, 25},

		{Undo, 0, 0},
	})

	testPosetOps(t, false, []posetTestOp{
		{Checkpoint, 0, 0},
		{SetOrderOrEqual, 10, 15},
		{SetOrderOrEqual, 15, 20},
		{SetOrderOrEqual, 20, 25},
		{SetOrder, 10, 16},
		{SetOrderOrEqual, 16, 20},
		// Check that we cannot collapse here because of the strict relation 10<16
		{SetOrderOrEqual_Fail, 20, 10},
		{Undo, 0, 0},
	})
}

func TestPosetSetEqual(t *testing.T) {
	testPosetOps(t, false, []posetTestOp{
		// 10<=20<=30<40,  20<=100<110
		{Checkpoint, 0, 0},
		{SetOrderOrEqual, 10, 20},
		{SetOrderOrEqual, 20, 30},
		{SetOrder, 30, 40},
		{SetOrderOrEqual, 20, 100},
		{SetOrder, 100, 110},
		{OrderedOrEqual, 10, 30},
		{OrderedOrEqual_Fail, 30, 10},
		{Ordered_Fail, 10, 30},
		{Ordered_Fail, 30, 10},
		{Ordered, 10, 40},
		{Ordered_Fail, 40, 10},

		// Try learning 10==20.
		{Checkpoint, 0, 0},
		{SetEqual, 10, 20},
		{OrderedOrEqual, 10, 20},
		{Ordered_Fail, 10, 20},
		{Equal, 10, 20},
		{SetOrderOrEqual, 10, 20},
		{SetOrderOrEqual, 20, 10},
		{SetOrder_Fail, 10, 20},
		{SetOrder_Fail, 20, 10},
		{Undo, 0, 0},

		// Try learning 20==10.
		{Checkpoint, 0, 0},
		{SetEqual, 20, 10},
		{OrderedOrEqual, 10, 20},
		{Ordered_Fail, 10, 20},
		{Equal, 10, 20},
		{Undo, 0, 0},

		// Try learning 10==40 or 30==40 or 10==110.
		{Checkpoint, 0, 0},
		{SetEqual_Fail, 10, 40},
		{SetEqual_Fail, 40, 10},
		{SetEqual_Fail, 30, 40},
		{SetEqual_Fail, 40, 30},
		{SetEqual_Fail, 10, 110},
		{SetEqual_Fail, 110, 10},
		{Undo, 0, 0},

		// Try learning 40==110, and then 10==40 or 10=110
		{Checkpoint, 0, 0},
		{SetEqual, 40, 110},
		{SetEqual_Fail, 10, 40},
		{SetEqual_Fail, 40, 10},
		{SetEqual_Fail, 10, 110},
		{SetEqual_Fail, 110, 10},
		{Undo, 0, 0},

		// Try learning 40<20 or 30<20 or 110<10
		{Checkpoint, 0, 0},
		{SetOrder_Fail, 40, 20},
		{SetOrder_Fail, 30, 20},
		{SetOrder_Fail, 110, 10},
		{Undo, 0, 0},

		// Try learning 30<=20
		{Checkpoint, 0, 0},
		{SetOrderOrEqual, 30, 20},
		{Equal, 30, 20},
		{OrderedOrEqual, 30, 100},
		{Ordered, 30, 110},
		{Undo, 0, 0},

		{Undo, 0, 0},
	})
}

func TestPosetNonEqual(t *testing.T) {
	testPosetOps(t, false, []posetTestOp{
		{Equal_Fail, 10, 20},
		{NonEqual_Fail, 10, 20},

		// Learn 10!=20
		{Checkpoint, 0, 0},
		{SetNonEqual, 10, 20},
		{Equal_Fail, 10, 20},
		{NonEqual, 10, 20},
		{SetEqual_Fail, 10, 20},

		// Learn again 10!=20
		{Checkpoint, 0, 0},
		{SetNonEqual, 10, 20},
		{Equal_Fail, 10, 20},
		{NonEqual, 10, 20},

		// Undo. We still know 10!=20
		{Undo, 0, 0},
		{Equal_Fail, 10, 20},
		{NonEqual, 10, 20},
		{SetEqual_Fail, 10, 20},

		// Undo again. Now we know nothing
		{Undo, 0, 0},
		{Equal_Fail, 10, 20},
		{NonEqual_Fail, 10, 20},

		// Learn 10==20
		{Checkpoint, 0, 0},
		{SetEqual, 10, 20},
		{Equal, 10, 20},
		{NonEqual_Fail, 10, 20},
		{SetNonEqual_Fail, 10, 20},

		// Learn again 10==20
		{Checkpoint, 0, 0},
		{SetEqual, 10, 20},
		{Equal, 10, 20},
		{NonEqual_Fail, 10, 20},
		{SetNonEqual_Fail, 10, 20},

		// Undo. We still know 10==20
		{Undo, 0, 0},
		{Equal, 10, 20},
		{NonEqual_Fail, 10, 20},
		{SetNonEqual_Fail, 10, 20},

		// Undo. We know nothing
		{Undo, 0, 0},
		{Equal_Fail, 10, 20},
		{NonEqual_Fail, 10, 20},
	})
}
```