Response:
Let's break down the thought process for analyzing the provided Go code.

**1. Initial Understanding: What is the File About?**

The filename `dom_test.go` strongly suggests that this file contains tests related to "dominance" in the context of program control flow graphs. The package declaration `package ssa` confirms it's part of the SSA (Static Single Assignment) representation within the Go compiler.

**2. High-Level Structure Analysis:**

* **Imports:**  `cmd/compile/internal/types` and `testing`. This indicates the code interacts with Go's type system and uses the standard `testing` package for writing unit tests and benchmarks.
* **Benchmark Functions:**  Functions starting with `Benchmark` are performance tests. The names (`BenchmarkDominatorsLinear`, etc.) hint at different graph structures being used for benchmarking the dominator calculation.
* **`blockGen` Type:** This defines a function type that generates blocks, suggesting different ways to construct control flow graphs for testing.
* **`gen...` Functions:** These are implementations of `blockGen`, each creating a specific type of control flow graph (linear, forward/backward branches, many predecessors, etc.). Analyzing these functions is crucial to understanding the test scenarios.
* **`benchmarkDominators` Function:** This is the core benchmarking function, taking a graph generation function as input and measuring the time it takes to compute dominators.
* **`domFunc` Type:**  A function type representing different dominator calculation algorithms.
* **`verifyDominators` Function:** This is the central testing function. It takes a function, a dominator calculation function, and a map of expected dominators. It verifies the calculated dominators against the expected ones.
* **`Test...` Functions:**  Standard Go test functions. Each tests the dominator calculation on a specific, manually constructed control flow graph. The `doms` map within each test defines the expected dominator relationships.
* **`generateDominatorMap` Function:**  This uses a "simple" dominator algorithm to create a ground truth for testing more complex algorithms.
* **`TestDominatorsPostTricky...` and `testDominatorsPostTricky`:**  These test a more intricate control flow graph, likely designed to expose edge cases in the dominator calculation.

**3. Deep Dive into Key Functions:**

* **`genLinear`:**  The simplest case: a straight line of blocks. This is a good baseline for testing.
* **`genFwdBack`:** Introduces conditional branches, making the control flow more complex. The `i % 2` creates an alternating pattern.
* **`genManyPred`:** Focuses on blocks with multiple incoming edges, crucial for testing how dominator algorithms handle merge points.
* **`genMaxPred` and `genMaxPredValue`:** Specifically designed to maximize the number of predecessors to the "exit" block. The `genMaxPredValue` variation likely tests the impact of having values within the blocks.
* **`benchmarkDominators`:** Note the `CheckFunc(fun.f)` call. This suggests that some validation of the generated function's structure happens before the actual benchmarking. The `b.SetBytes` and `b.ResetTimer` are standard benchmarking practices.
* **`verifyDominators`:**  The core logic here is to compare the calculated dominators (from `domFn`) with the expected dominators (in the `doms` map). It iterates through the expected dominators and checks if they match. It also checks for unexpected dominators in the calculated result.

**4. Inferring the Implemented Go Feature:**

Based on the function names, the focus on control flow graphs, and the terminology ("dominators," "blocks," "SSA"), it's highly probable that this code is testing the implementation of **dominance analysis** within the Go compiler's SSA backend. Dominance analysis is a fundamental static analysis technique used in compilers for various optimizations, such as identifying loop invariants, performing dead code elimination, and constructing control dependence graphs.

**5. Code Example and Reasoning:**

To illustrate dominance, consider a simple example:

```go
// Simplified representation of blocks (not the exact struct in the code)
type Block struct {
	Name     string
	Predecessors []*Block
	Successors   []*Block
}

// ... (Building the graph)

// Dominance definition: Block A dominates Block B if every path from the entry
// node to B must pass through A.

// Example Graph:
// entry -> a -> b -> exit
//        -> c ----^

// Dominators:
// entry: entry
// a:     entry
// b:     a
// c:     entry
// exit:  b (or potentially entry, depending on the exact definition used)
```

The test code uses functions like `genFwdBack` and `genManyPred` to create graphs that test different dominance relationships. For instance, in `genManyPred`, blocks can have multiple predecessors, which challenges the dominator calculation.

**6. Command-Line Parameters:**

Since this is test code, it doesn't directly process command-line arguments in the way a typical Go program does. The `testing` package handles running the benchmarks and tests. You would use `go test` with flags like `-bench` to run the benchmarks and potentially `-run` to run specific tests.

**7. Common Mistakes:**

The tests themselves highlight potential errors in dominator calculation. The "Tricky" tests (like `TestDomTricky` and `TestDominatorsPostTricky`) are specifically designed to catch cases where a naive algorithm might produce incorrect results. A common mistake in implementing dominator algorithms is incorrectly handling merge points (nodes with multiple predecessors). The `TestDominatorsMultPred...` tests are likely targeted at this.

**8. Self-Correction/Refinement:**

Initially, I might have just focused on the `dominators` function. However, by looking at the `verifyDominators` function and the various `gen...` functions, it became clear that the *testing* of the dominator algorithm is the primary purpose of this code. The different graph generation functions are essential for creating diverse test scenarios. Also, the existence of both `dominators` and `dominatorsSimple` suggests they are comparing different implementations or levels of optimization of the dominator calculation.

This detailed breakdown allows for a comprehensive understanding of the provided code snippet.
这是 `go/src/cmd/compile/internal/ssa/dom_test.go` 文件的一部分，它主要的功能是**测试 SSA 中支配关系（Dominance）的计算**。

更具体地说，它包含了一系列用于测试 `cmd/compile/internal/ssa` 包中计算程序控制流图中支配节点算法的基准测试和单元测试。

以下是代码片段中各个部分的功能分解：

**1. 基准测试 (Benchmarks):**

* `BenchmarkDominatorsLinear`: 测试在**线性**控制流图上计算支配关系的性能。
* `BenchmarkDominatorsFwdBack`: 测试在具有**前向和后向分支**的控制流图上计算支配关系的性能。
* `BenchmarkDominatorsManyPred`: 测试在节点具有**多个前驱**的控制流图上计算支配关系的性能。
* `BenchmarkDominatorsMaxPred`: 测试在**出口节点具有最大数量前驱**的控制流图上计算支配关系的性能。
* `BenchmarkDominatorsMaxPredVal`: 类似于 `BenchmarkDominatorsMaxPred`，但控制流图中包含**额外的 Value** 节点。

这些基准测试使用不同的控制流图结构（由 `genLinear` 等函数生成）来评估支配关系算法在不同场景下的性能。

**2. 控制流图生成函数 (`blockGen` 和 `gen...`):**

* `type blockGen func(size int) []bloc`: 定义了一个函数类型 `blockGen`，它接收一个整数 `size` 并返回一个 `[]bloc`，用于生成控制流图的块 (block)。
* `genLinear(size int) []bloc`: 生成一个**线性**的控制流图，每个块都只有一个后继块。
    * **假设输入:** `size = 3`
    * **输出 (简化表示):** `entry -> block0 -> block1 -> block2 -> exit`
* `genFwdBack(size int) []bloc`: 生成一个具有**前向和后向分支**的控制流图。每个块可能会跳转到下一个块，或者跳回到之前的块。
    * **假设输入:** `size = 3`
    * **输出 (简化表示):**  `entry -> block0 (if) -> block1 (if) -> block2 -> exit`，其中 `block0` 可能跳转到 `block1` 或 `block2`，`block1` 可能跳转到 `block2` 或 `block0`。
* `genManyPred(size int) []bloc`: 生成一个控制流图，其中一部分块会跳转到**第一个块**，一部分会跳转到**最后一个块**，剩余的块是普通的连接。
    * **假设输入:** `size = 3`
    * **输出 (简化表示):** `entry -> block0 (goto) -> block1 (if) -> block2 (if) -> exit`，其中 `block1` 可能跳转到 `block2` 或 `block0`，`block2` 可能跳转到 `block3` 或 `exit`。
* `genMaxPred(size int) []bloc`: 生成一个控制流图，**最大化了出口块的前驱数量**。大部分块都有条件跳转到下一个块或出口块。
    * **假设输入:** `size = 3`
    * **输出 (简化表示):** `entry -> block0 (if) -> block1 (if) -> block2 (if) -> exit`，其中 `block0`, `block1`, `block2` 都可能跳转到 `exit`。
* `genMaxPredValue(size int) []bloc`: 和 `genMaxPred` 类似，但在每个块中添加了一个额外的 `Value` 节点。

这些生成函数模拟了不同复杂度的控制流结构，用于更全面地测试支配关系算法。

**3. 支配关系验证函数:**

* `verifyDominators(t *testing.T, fut fun, domFn domFunc, doms map[string]string)`:  这个函数是核心的测试逻辑。
    * 它接收一个测试对象 `t`，被测试的函数 `fut` (包含控制流图)，一个支配关系计算函数 `domFn`，以及一个期望的支配关系映射 `doms`。
    * 它首先将 `Block` 指针映射到其名称，方便比较。
    * 然后调用 `domFn` 计算支配关系。
    * 接着遍历期望的支配关系 `doms`，检查计算出的支配节点是否与期望的匹配。
    * 最后，它还会检查计算出的支配关系中是否有不期望的条目。

**4. 单元测试 (Tests):**

* `TestDominatorsSingleBlock`: 测试只有一个块的控制流图的支配关系。
* `TestDominatorsSimple`: 测试一个简单的线性控制流图的支配关系。
* `TestDominatorsMultPredFwd`: 测试具有前向多条路径汇聚的控制流图的支配关系。
* `TestDominatorsDeadCode`: 测试包含死代码的控制流图的支配关系。
* `TestDominatorsMultPredRev`: 测试具有反向多条路径汇聚的控制流图的支配关系。
* `TestDominatorsMultPred`: 测试具有多条路径汇聚的控制流图的支配关系。
* `TestInfiniteLoop`: 测试包含无限循环的控制流图的支配关系。
* `TestDomTricky`: 一个设计用于测试复杂场景的控制流图，其中包含了条件分支和多条路径。
* `TestDominatorsPostTrickyA` 到 `TestDominatorsPostTrickyH`:  一系列更复杂的测试用例，旨在测试特定类型的控制流结构中的支配关系。

每个单元测试都构造了一个特定的控制流图，并使用 `verifyDominators` 函数来验证计算出的支配关系是否正确。

**5. 辅助函数:**

* `benchmarkDominators(b *testing.B, size int, bg blockGen)`:  执行基准测试的通用函数。它创建一个指定大小和结构的函数，然后多次运行支配关系计算并记录时间。
* `generateDominatorMap(fut fun) map[string]string`:  使用一个简单的支配关系计算算法 `dominatorsSimple` 来生成一个参考的支配关系映射，用于测试更复杂的算法。

**可以推理出它是什么 go 语言功能的实现:**

从代码的结构和测试目标来看，这段代码是用于测试 Go 编译器中 **SSA 中支配关系计算**功能的实现。支配关系是控制流分析中的一个重要概念，用于确定程序中哪些代码块的执行必须先于其他代码块的执行。这在编译器优化（如死代码消除、循环不变式外提等）中至关重要。

**Go 代码举例说明 (简化):**

假设我们有一个简单的 Go 函数：

```go
package main

func foo(x int) int {
	if x > 0 {
		x = x * 2
	} else {
		x = -x
	}
	return x
}
```

这段代码对应的控制流图可以抽象成以下几个基本块：

1. **Entry:** 函数入口。
2. **Condition:** 判断 `x > 0` 的条件。
3. **Then:**  `x = x * 2` 的代码块。
4. **Else:** `x = -x` 的代码块。
5. **Return:** 返回 `x` 的代码块。

在这个控制流图中，各个块的支配关系如下：

* **Entry** 支配所有其他块。
* **Condition** 支配 **Then** 和 **Else** 块。
* **Return** 支配自身。

`dom_test.go` 中的代码就是为了验证编译器是否能正确计算出这种支配关系。

**使用者易犯错的点 (可能在实现支配关系算法时):**

* **未正确处理控制流图的环 (Loops):**  计算支配关系在存在环的情况下会更复杂，需要迭代计算直到收敛。
* **未正确处理不可达代码 (Dead Code):**  不可达的代码块没有支配节点（除了自身）。
* **初始化的错误:**  在迭代计算支配关系时，初始值的选择会影响效率和正确性。
* **性能问题:**  对于大型的控制流图，计算支配关系的效率可能是一个问题。

**命令行参数的具体处理:**

此文件是测试文件，不直接处理命令行参数。当使用 `go test` 命令运行测试时，`testing` 包会负责处理相关的测试标志，例如：

* `-bench <regexp>`: 运行匹配正则表达式的基准测试。例如，`go test -bench=.` 将运行所有基准测试。
* `-run <regexp>`: 运行匹配正则表达式的单元测试。例如，`go test -run=TestDominatorsSimple` 将只运行 `TestDominatorsSimple` 测试。
* `-v`:  显示更详细的测试输出。

总而言之，`go/src/cmd/compile/internal/ssa/dom_test.go` 是 Go 编译器中 SSA 阶段关键的测试文件，用于确保支配关系计算的正确性和性能，这对于编译器的代码优化至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/dom_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

import (
	"cmd/compile/internal/types"
	"testing"
)

func BenchmarkDominatorsLinear(b *testing.B)     { benchmarkDominators(b, 10000, genLinear) }
func BenchmarkDominatorsFwdBack(b *testing.B)    { benchmarkDominators(b, 10000, genFwdBack) }
func BenchmarkDominatorsManyPred(b *testing.B)   { benchmarkDominators(b, 10000, genManyPred) }
func BenchmarkDominatorsMaxPred(b *testing.B)    { benchmarkDominators(b, 10000, genMaxPred) }
func BenchmarkDominatorsMaxPredVal(b *testing.B) { benchmarkDominators(b, 10000, genMaxPredValue) }

type blockGen func(size int) []bloc

// genLinear creates an array of blocks that succeed one another
// b_n -> [b_n+1].
func genLinear(size int) []bloc {
	var blocs []bloc
	blocs = append(blocs,
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Goto(blockn(0)),
		),
	)
	for i := 0; i < size; i++ {
		blocs = append(blocs, Bloc(blockn(i),
			Goto(blockn(i+1))))
	}

	blocs = append(blocs,
		Bloc(blockn(size), Goto("exit")),
		Bloc("exit", Exit("mem")),
	)

	return blocs
}

// genFwdBack creates an array of blocks that alternate between
// b_n -> [b_n+1], b_n -> [b_n+1, b_n-1] , b_n -> [b_n+1, b_n+2]
func genFwdBack(size int) []bloc {
	var blocs []bloc
	blocs = append(blocs,
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("p", OpConstBool, types.Types[types.TBOOL], 1, nil),
			Goto(blockn(0)),
		),
	)
	for i := 0; i < size; i++ {
		switch i % 2 {
		case 0:
			blocs = append(blocs, Bloc(blockn(i),
				If("p", blockn(i+1), blockn(i+2))))
		case 1:
			blocs = append(blocs, Bloc(blockn(i),
				If("p", blockn(i+1), blockn(i-1))))
		}
	}

	blocs = append(blocs,
		Bloc(blockn(size), Goto("exit")),
		Bloc("exit", Exit("mem")),
	)

	return blocs
}

// genManyPred creates an array of blocks where 1/3rd have a successor of the
// first block, 1/3rd the last block, and the remaining third are plain.
func genManyPred(size int) []bloc {
	var blocs []bloc
	blocs = append(blocs,
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("p", OpConstBool, types.Types[types.TBOOL], 1, nil),
			Goto(blockn(0)),
		),
	)

	// We want predecessor lists to be long, so 2/3rds of the blocks have a
	// successor of the first or last block.
	for i := 0; i < size; i++ {
		switch i % 3 {
		case 0:
			blocs = append(blocs, Bloc(blockn(i),
				Valu("a", OpConstBool, types.Types[types.TBOOL], 1, nil),
				Goto(blockn(i+1))))
		case 1:
			blocs = append(blocs, Bloc(blockn(i),
				Valu("a", OpConstBool, types.Types[types.TBOOL], 1, nil),
				If("p", blockn(i+1), blockn(0))))
		case 2:
			blocs = append(blocs, Bloc(blockn(i),
				Valu("a", OpConstBool, types.Types[types.TBOOL], 1, nil),
				If("p", blockn(i+1), blockn(size))))
		}
	}

	blocs = append(blocs,
		Bloc(blockn(size), Goto("exit")),
		Bloc("exit", Exit("mem")),
	)

	return blocs
}

// genMaxPred maximizes the size of the 'exit' predecessor list.
func genMaxPred(size int) []bloc {
	var blocs []bloc
	blocs = append(blocs,
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("p", OpConstBool, types.Types[types.TBOOL], 1, nil),
			Goto(blockn(0)),
		),
	)

	for i := 0; i < size; i++ {
		blocs = append(blocs, Bloc(blockn(i),
			If("p", blockn(i+1), "exit")))
	}

	blocs = append(blocs,
		Bloc(blockn(size), Goto("exit")),
		Bloc("exit", Exit("mem")),
	)

	return blocs
}

// genMaxPredValue is identical to genMaxPred but contains an
// additional value.
func genMaxPredValue(size int) []bloc {
	var blocs []bloc
	blocs = append(blocs,
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("p", OpConstBool, types.Types[types.TBOOL], 1, nil),
			Goto(blockn(0)),
		),
	)

	for i := 0; i < size; i++ {
		blocs = append(blocs, Bloc(blockn(i),
			Valu("a", OpConstBool, types.Types[types.TBOOL], 1, nil),
			If("p", blockn(i+1), "exit")))
	}

	blocs = append(blocs,
		Bloc(blockn(size), Goto("exit")),
		Bloc("exit", Exit("mem")),
	)

	return blocs
}

// sink for benchmark
var domBenchRes []*Block

func benchmarkDominators(b *testing.B, size int, bg blockGen) {
	c := testConfig(b)
	fun := c.Fun("entry", bg(size)...)

	CheckFunc(fun.f)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		domBenchRes = dominators(fun.f)
	}
}

type domFunc func(f *Func) []*Block

// verifyDominators verifies that the dominators of fut (function under test)
// as determined by domFn, match the map node->dominator
func verifyDominators(t *testing.T, fut fun, domFn domFunc, doms map[string]string) {
	blockNames := map[*Block]string{}
	for n, b := range fut.blocks {
		blockNames[b] = n
	}

	calcDom := domFn(fut.f)

	for n, d := range doms {
		nblk, ok := fut.blocks[n]
		if !ok {
			t.Errorf("invalid block name %s", n)
		}
		dblk, ok := fut.blocks[d]
		if !ok {
			t.Errorf("invalid block name %s", d)
		}

		domNode := calcDom[nblk.ID]
		switch {
		case calcDom[nblk.ID] == dblk:
			calcDom[nblk.ID] = nil
			continue
		case calcDom[nblk.ID] != dblk:
			t.Errorf("expected %s as dominator of %s, found %s", d, n, blockNames[domNode])
		default:
			t.Fatal("unexpected dominator condition")
		}
	}

	for id, d := range calcDom {
		// If nil, we've already verified it
		if d == nil {
			continue
		}
		for _, b := range fut.blocks {
			if int(b.ID) == id {
				t.Errorf("unexpected dominator of %s for %s", blockNames[d], blockNames[b])
			}
		}
	}

}

func TestDominatorsSingleBlock(t *testing.T) {
	c := testConfig(t)
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Exit("mem")))

	doms := map[string]string{}

	CheckFunc(fun.f)
	verifyDominators(t, fun, dominators, doms)
	verifyDominators(t, fun, dominatorsSimple, doms)

}

func TestDominatorsSimple(t *testing.T) {
	c := testConfig(t)
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Goto("a")),
		Bloc("a",
			Goto("b")),
		Bloc("b",
			Goto("c")),
		Bloc("c",
			Goto("exit")),
		Bloc("exit",
			Exit("mem")))

	doms := map[string]string{
		"a":    "entry",
		"b":    "a",
		"c":    "b",
		"exit": "c",
	}

	CheckFunc(fun.f)
	verifyDominators(t, fun, dominators, doms)
	verifyDominators(t, fun, dominatorsSimple, doms)

}

func TestDominatorsMultPredFwd(t *testing.T) {
	c := testConfig(t)
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("p", OpConstBool, types.Types[types.TBOOL], 1, nil),
			If("p", "a", "c")),
		Bloc("a",
			If("p", "b", "c")),
		Bloc("b",
			Goto("c")),
		Bloc("c",
			Goto("exit")),
		Bloc("exit",
			Exit("mem")))

	doms := map[string]string{
		"a":    "entry",
		"b":    "a",
		"c":    "entry",
		"exit": "c",
	}

	CheckFunc(fun.f)
	verifyDominators(t, fun, dominators, doms)
	verifyDominators(t, fun, dominatorsSimple, doms)
}

func TestDominatorsDeadCode(t *testing.T) {
	c := testConfig(t)
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("p", OpConstBool, types.Types[types.TBOOL], 0, nil),
			If("p", "b3", "b5")),
		Bloc("b2", Exit("mem")),
		Bloc("b3", Goto("b2")),
		Bloc("b4", Goto("b2")),
		Bloc("b5", Goto("b2")))

	doms := map[string]string{
		"b2": "entry",
		"b3": "entry",
		"b5": "entry",
	}

	CheckFunc(fun.f)
	verifyDominators(t, fun, dominators, doms)
	verifyDominators(t, fun, dominatorsSimple, doms)
}

func TestDominatorsMultPredRev(t *testing.T) {
	c := testConfig(t)
	fun := c.Fun("entry",
		Bloc("entry",
			Goto("first")),
		Bloc("first",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("p", OpConstBool, types.Types[types.TBOOL], 1, nil),
			Goto("a")),
		Bloc("a",
			If("p", "b", "first")),
		Bloc("b",
			Goto("c")),
		Bloc("c",
			If("p", "exit", "b")),
		Bloc("exit",
			Exit("mem")))

	doms := map[string]string{
		"first": "entry",
		"a":     "first",
		"b":     "a",
		"c":     "b",
		"exit":  "c",
	}

	CheckFunc(fun.f)
	verifyDominators(t, fun, dominators, doms)
	verifyDominators(t, fun, dominatorsSimple, doms)
}

func TestDominatorsMultPred(t *testing.T) {
	c := testConfig(t)
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("p", OpConstBool, types.Types[types.TBOOL], 1, nil),
			If("p", "a", "c")),
		Bloc("a",
			If("p", "b", "c")),
		Bloc("b",
			Goto("c")),
		Bloc("c",
			If("p", "b", "exit")),
		Bloc("exit",
			Exit("mem")))

	doms := map[string]string{
		"a":    "entry",
		"b":    "entry",
		"c":    "entry",
		"exit": "c",
	}

	CheckFunc(fun.f)
	verifyDominators(t, fun, dominators, doms)
	verifyDominators(t, fun, dominatorsSimple, doms)
}

func TestInfiniteLoop(t *testing.T) {
	c := testConfig(t)
	// note lack of an exit block
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("p", OpConstBool, types.Types[types.TBOOL], 1, nil),
			Goto("a")),
		Bloc("a",
			Goto("b")),
		Bloc("b",
			Goto("a")))

	CheckFunc(fun.f)
	doms := map[string]string{"a": "entry",
		"b": "a"}
	verifyDominators(t, fun, dominators, doms)
}

func TestDomTricky(t *testing.T) {
	doms := map[string]string{
		"4":  "1",
		"2":  "4",
		"5":  "4",
		"11": "4",
		"15": "4", // the incorrect answer is "5"
		"10": "15",
		"19": "15",
	}

	if4 := [2]string{"2", "5"}
	if5 := [2]string{"15", "11"}
	if15 := [2]string{"19", "10"}

	for i := 0; i < 8; i++ {
		a := 1 & i
		b := 1 & i >> 1
		c := 1 & i >> 2

		cfg := testConfig(t)
		fun := cfg.Fun("1",
			Bloc("1",
				Valu("mem", OpInitMem, types.TypeMem, 0, nil),
				Valu("p", OpConstBool, types.Types[types.TBOOL], 1, nil),
				Goto("4")),
			Bloc("2",
				Goto("11")),
			Bloc("4",
				If("p", if4[a], if4[1-a])), // 2, 5
			Bloc("5",
				If("p", if5[b], if5[1-b])), //15, 11
			Bloc("10",
				Exit("mem")),
			Bloc("11",
				Goto("15")),
			Bloc("15",
				If("p", if15[c], if15[1-c])), //19, 10
			Bloc("19",
				Goto("10")))
		CheckFunc(fun.f)
		verifyDominators(t, fun, dominators, doms)
		verifyDominators(t, fun, dominatorsSimple, doms)
	}
}

// generateDominatorMap uses dominatorsSimple to obtain a
// reference dominator tree for testing faster algorithms.
func generateDominatorMap(fut fun) map[string]string {
	blockNames := map[*Block]string{}
	for n, b := range fut.blocks {
		blockNames[b] = n
	}
	referenceDom := dominatorsSimple(fut.f)
	doms := make(map[string]string)
	for _, b := range fut.f.Blocks {
		if d := referenceDom[b.ID]; d != nil {
			doms[blockNames[b]] = blockNames[d]
		}
	}
	return doms
}

func TestDominatorsPostTrickyA(t *testing.T) {
	testDominatorsPostTricky(t, "b8", "b11", "b10", "b8", "b14", "b15")
}

func TestDominatorsPostTrickyB(t *testing.T) {
	testDominatorsPostTricky(t, "b11", "b8", "b10", "b8", "b14", "b15")
}

func TestDominatorsPostTrickyC(t *testing.T) {
	testDominatorsPostTricky(t, "b8", "b11", "b8", "b10", "b14", "b15")
}

func TestDominatorsPostTrickyD(t *testing.T) {
	testDominatorsPostTricky(t, "b11", "b8", "b8", "b10", "b14", "b15")
}

func TestDominatorsPostTrickyE(t *testing.T) {
	testDominatorsPostTricky(t, "b8", "b11", "b10", "b8", "b15", "b14")
}

func TestDominatorsPostTrickyF(t *testing.T) {
	testDominatorsPostTricky(t, "b11", "b8", "b10", "b8", "b15", "b14")
}

func TestDominatorsPostTrickyG(t *testing.T) {
	testDominatorsPostTricky(t, "b8", "b11", "b8", "b10", "b15", "b14")
}

func TestDominatorsPostTrickyH(t *testing.T) {
	testDominatorsPostTricky(t, "b11", "b8", "b8", "b10", "b15", "b14")
}

func testDominatorsPostTricky(t *testing.T, b7then, b7else, b12then, b12else, b13then, b13else string) {
	c := testConfig(t)
	fun := c.Fun("b1",
		Bloc("b1",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("p", OpConstBool, types.Types[types.TBOOL], 1, nil),
			If("p", "b3", "b2")),
		Bloc("b3",
			If("p", "b5", "b6")),
		Bloc("b5",
			Goto("b7")),
		Bloc("b7",
			If("p", b7then, b7else)),
		Bloc("b8",
			Goto("b13")),
		Bloc("b13",
			If("p", b13then, b13else)),
		Bloc("b14",
			Goto("b10")),
		Bloc("b15",
			Goto("b16")),
		Bloc("b16",
			Goto("b9")),
		Bloc("b9",
			Goto("b7")),
		Bloc("b11",
			Goto("b12")),
		Bloc("b12",
			If("p", b12then, b12else)),
		Bloc("b10",
			Goto("b6")),
		Bloc("b6",
			Goto("b17")),
		Bloc("b17",
			Goto("b18")),
		Bloc("b18",
			If("p", "b22", "b19")),
		Bloc("b22",
			Goto("b23")),
		Bloc("b23",
			If("p", "b21", "b19")),
		Bloc("b19",
			If("p", "b24", "b25")),
		Bloc("b24",
			Goto("b26")),
		Bloc("b26",
			Goto("b25")),
		Bloc("b25",
			If("p", "b27", "b29")),
		Bloc("b27",
			Goto("b30")),
		Bloc("b30",
			Goto("b28")),
		Bloc("b29",
			Goto("b31")),
		Bloc("b31",
			Goto("b28")),
		Bloc("b28",
			If("p", "b32", "b33")),
		Bloc("b32",
			Goto("b21")),
		Bloc("b21",
			Goto("b47")),
		Bloc("b47",
			If("p", "b45", "b46")),
		Bloc("b45",
			Goto("b48")),
		Bloc("b48",
			Goto("b49")),
		Bloc("b49",
			If("p", "b50", "b51")),
		Bloc("b50",
			Goto("b52")),
		Bloc("b52",
			Goto("b53")),
		Bloc("b53",
			Goto("b51")),
		Bloc("b51",
			Goto("b54")),
		Bloc("b54",
			Goto("b46")),
		Bloc("b46",
			Exit("mem")),
		Bloc("b33",
			Goto("b34")),
		Bloc("b34",
			Goto("b37")),
		Bloc("b37",
			If("p", "b35", "b36")),
		Bloc("b35",
			Goto("b38")),
		Bloc("b38",
			Goto("b39")),
		Bloc("b39",
			If("p", "b40", "b41")),
		Bloc("b40",
			Goto("b42")),
		Bloc("b42",
			Goto("b43")),
		Bloc("b43",
			Goto("b41")),
		Bloc("b41",
			Goto("b44")),
		Bloc("b44",
			Goto("b36")),
		Bloc("b36",
			Goto("b20")),
		Bloc("b20",
			Goto("b18")),
		Bloc("b2",
			Goto("b4")),
		Bloc("b4",
			Exit("mem")))
	CheckFunc(fun.f)
	doms := generateDominatorMap(fun)
	verifyDominators(t, fun, dominators, doms)
}
```