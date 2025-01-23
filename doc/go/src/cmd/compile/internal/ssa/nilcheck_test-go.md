Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Context:** The first step is to recognize that this code lives within the Go compiler (`cmd/compile`) and specifically in the `ssa` (Static Single Assignment) package. This immediately tells us it's dealing with low-level code transformations and optimizations. The filename `nilcheck_test.go` strongly suggests its purpose: testing the elimination of redundant nil checks.

2. **Identify Key Functions and Structures:**  Scanning the code, certain functions and data structures stand out:
    * `BenchmarkNilCheckDeep`: This clearly performs benchmarking to measure the performance of some operation related to nil checks. The "Deep" suffix and the loop suggest it's testing scenarios with varying numbers of checks.
    * `benchmarkNilCheckDeep`: This is the function actually doing the benchmark setup. It constructs a control flow graph (`blocs`) with a linear sequence of nil checks.
    * `TestNilcheck...`: Several functions starting with `TestNilcheck` are present, indicating unit tests for different nil check elimination scenarios.
    * `nilcheckelim`: This function name is the most crucial. It strongly implies this is the core function being tested – the nil check elimination pass itself.
    * `CheckFunc`:  This likely performs some kind of validation or consistency check on the function's SSA representation.
    * `fuse`, `deadcode`: These are standard compiler optimization passes for cleaning up the control flow graph after other transformations.
    * `Bloc`, `Valu`, `Goto`, `If`, `Exit`: These likely represent nodes in the SSA control flow graph (blocks and values).
    * `OpIsNonNil`, `OpAddr`, `OpLoad`, `OpAddPtr`, `OpPhi`, `OpNeqPtr`, `OpConstNil`, `OpStore`, `OpInitMem`, `OpSB`, `OpSP`, `OpLocalAddr`, `OpConst64`: These are SSA operation codes, hinting at the different ways nil checks and pointer manipulations can occur.
    * `testConfig`, `Fun`: These seem to be helper functions for setting up test environments and constructing SSA functions.

3. **Infer Functionality of `nilcheckelim`:** Based on the surrounding code and the test names, the primary function of `nilcheckelim` is to identify and remove redundant nil checks in the SSA representation of a Go function. A "redundant" nil check is one where the compiler can already guarantee that the pointer being checked is either nil or non-nil based on previous checks or operations.

4. **Analyze Individual Test Cases:**  Each `TestNilcheck...` function targets a specific scenario for nil check elimination:
    * `TestNilcheckSimple`:  Checks for the removal of a directly repeated nil check.
    * `TestNilcheckDomOrder`: Ensures the elimination works regardless of the order of blocks in the control flow graph.
    * `TestNilcheckAddr`, `TestNilcheckAddPtr`: Verifies elimination when the pointer's non-nullness is derived from `OpAddr` (address of) or `OpAddPtr` (pointer arithmetic).
    * `TestNilcheckPhi`: Tests elimination for `OpPhi` nodes, where multiple incoming paths guarantee a non-nil value.
    * `TestNilcheckKeepRemove`: Confirms that only *redundant* checks are removed, not all nil checks on different pointers.
    * `TestNilcheckInFalseBranch`:  Demonstrates that checks in the *false* branch of a prior nil check are *not* removed (as the pointer could be nil there).
    * `TestNilcheckUser`: Checks the interaction with explicit (user-written) nil checks using `OpNeqPtr`.
    * `TestNilcheckBug`: A regression test for a specific bug found during compilation of `math/big`.

5. **Construct Example Code:** Based on the understanding of `nilcheckelim` and the test cases, construct a simple Go example that demonstrates the optimization. The `TestNilcheckSimple` case provides a good starting point: a direct repetition of a nil check.

6. **Infer Command-Line Arguments and Error Points:** Since this is compiler-internal code and the tests are run within the Go test framework, there are no direct command-line arguments handled *by this specific file*. The benchmarking functions might be used with the standard Go benchmarking flags (e.g., `-bench`, `-count`). The potential error points are primarily related to incorrect assumptions made by the `nilcheckelim` pass, which the tests are designed to uncover. A common mistake would be removing a nil check that is actually necessary.

7. **Review and Refine:** Go back through the analysis and ensure clarity, accuracy, and completeness. For example, initially, I might have missed the significance of the `opt(fun.f)` call in `TestNilcheckUser` and `TestNilcheckBug`. Recognizing that this is needed to transform the user-written nil check (`OpNeqPtr`) into a form that `nilcheckelim` can understand is important. Also, double-check the SSA operation codes and their meanings.

This iterative process of understanding the context, identifying key elements, inferring functionality, analyzing examples, and refining the understanding allows for a comprehensive analysis of the provided code snippet.
这个文件 `go/src/cmd/compile/internal/ssa/nilcheck_test.go` 是 Go 编译器中 `ssa` 包的一部分，专门用于测试 **nil 检查消除（nil check elimination）** 这个编译优化过程。

**功能列表:**

1. **基准测试 (Benchmarking):**
   - `BenchmarkNilCheckDeep1` 到 `BenchmarkNilCheckDeep10000` 等函数用于衡量在不同深度（即连续的 nil 检查数量）下，nil 检查消除的性能。这有助于分析该优化的时间复杂度。
   - `benchmarkNilCheckDeep` 函数生成一个包含指定深度线性 nil 检查的 SSA 函数，用于压力测试 `nilcheckelim` 函数。

2. **单元测试 (Unit Testing):**
   - `TestNilcheckSimple`: 测试最简单的场景，即重复的 nil 检查是否能被消除。
   - `TestNilcheckDomOrder`: 测试 nil 检查消除是否依赖于支配关系（dominance）的顺序。
   - `TestNilcheckAddr`: 测试对 `OpAddr` 操作生成的指针的 nil 检查是否能被消除。 `OpAddr` 通常用于获取变量的地址，因此结果永远不会是 nil。
   - `TestNilcheckAddPtr`: 测试对 `OpAddPtr` 操作生成的指针的 nil 检查是否能被消除。 `OpAddPtr` 用于指针算术，如果基址非 nil，结果通常也非 nil。
   - `TestNilcheckPhi`: 测试当 `OpPhi` 节点的所有输入都保证非 nil 时，对其结果的 nil 检查是否能被消除。 `OpPhi` 用于合并不同控制流路径上的值。
   - `TestNilcheckKeepRemove`: 测试对于同一个指针的重复 nil 检查会被消除，但对不同指针的 nil 检查会保留。
   - `TestNilcheckInFalseBranch`: 测试在一个 nil 检查的 false 分支中的 nil 检查不会被消除，因为在 false 分支中指针可能为 nil。
   - `TestNilcheckUser`: 测试用户代码中的 nil 检查如果支配了编译器生成的 nil 检查，编译器生成的 nil 检查会被消除。
   - `TestNilcheckBug`:  再现并测试修复了一个在编译 `math/big` 包时发现的 nil 检查消除相关的 bug。

3. **辅助函数:**
   - `blockn`, `ptrn`, `booln`:  生成带有序号的 SSA 块、指针和布尔值的名称，方便在测试代码中构建 SSA 图。
   - `isNilCheck`: 判断一个 SSA 块是否是一个 nil 检查块（即以 `OpIsNonNil` 作为控制值的 `BlockIf` 块）。

**Go 语言功能实现推断 (Nil Check Elimination):**

这个文件测试的是 Go 编译器中用于优化代码的 **nil 检查消除** 功能。  当编译器能够静态地推断出一个指针永远不为 nil 时，就可以安全地移除对该指针的显式 nil 检查，从而提高代码的执行效率。

**Go 代码示例说明:**

假设我们有以下 Go 代码：

```go
package main

func foo(p *int) {
	if p != nil { // 用户显式 nil 检查
		println(*p)
	}
	if p != nil { // 编译器生成的隐式 nil 检查 (如果编译器不进行优化)
		println(*p)
	}
}

func main() {
	var x int = 10
	foo(&x)
}
```

在 `foo` 函数中，我们对指针 `p` 进行了两次 nil 检查。如果编译器进行了 nil 检查消除优化，那么第二个 `if p != nil` 检查可能会被移除，因为编译器可以推断出如果代码执行到这里，`p` 肯定不是 `nil`（因为第一个 `if` 已经做了判断）。

**假设的输入与输出 (针对 `TestNilcheckSimple`):**

**输入 (构建的 SSA 函数 `fun.f`):**

```
entry:
  v1 = InitMem {mem}
  v2 = SB {}
  goto checkPtr
checkPtr:
  v3 = Load {ptr} v2, v1
  v4 = IsNonNil {bool} v3
  if v4 goto secondCheck else exit
secondCheck:
  v5 = IsNonNil {bool} v3
  if v5 goto extra else exit
extra:
  goto exit
exit:
  v6 = Exit {mem}
```

**输出 (经过 `nilcheckelim`、`fuse` 和 `deadcode` 优化后的 SSA 函数):**

```
entry:
  v1 = InitMem {mem}
  v2 = SB {}
  goto checkPtr
checkPtr:
  v3 = Load {ptr} v2, v1
  v4 = IsNonNil {bool} v3
  if v4 goto extra else exit // 第二个 nil check 相关的块被消除
extra:
  goto exit
exit:
  v6 = Exit {mem}
```

可以看到，`secondCheck` 块及其相关的 `OpIsNonNil` 操作被移除了。

**命令行参数的具体处理:**

此代码是测试代码，本身不直接处理命令行参数。它依赖 Go 的 `testing` 包来运行。可以通过 `go test` 命令来执行这些测试，例如：

```bash
go test -run TestNilcheckSimple ./go/src/cmd/compile/internal/ssa
go test -bench BenchmarkNilCheckDeep ./go/src/cmd/compile/internal/ssa
```

* `-run`:  指定要运行的测试函数。
* `-bench`: 指定要运行的基准测试函数。

**使用者易犯错的点 (虽然这是编译器内部代码的测试，但可以引申到 Go 开发者):**

虽然普通 Go 开发者不会直接使用这些测试代码，但了解 nil 检查消除的原理有助于理解 Go 代码的性能。一个可能相关的误解是：

* **过度依赖显式的 nil 检查:**  有时开发者会在已经确定指针非 nil 的情况下仍然进行显式的 nil 检查。虽然这不会导致错误，但可能会影响性能，并且使代码看起来冗余。编译器在某些情况下可以优化掉这些冗余的检查，但这并不意味着应该滥用。

**例子:**

```go
package main

type MyStruct struct {
	Value int
}

func process(s *MyStruct) {
	if s == nil { // 假设这里已经通过某种方式保证 s 不为 nil
		return
	}
	println(s.Value)
	if s != nil { // 冗余的 nil 检查
		println(s.Value * 2)
	}
}

func main() {
	s := &MyStruct{Value: 5}
	process(s)
}
```

在 `process` 函数中，第二个 `if s != nil` 检查是冗余的，因为在执行到那里时，`s` 肯定不是 `nil`。编译器可能会消除这个检查，但编写清晰简洁的代码仍然很重要。

总而言之，`nilcheck_test.go` 这个文件是 Go 编译器中用于测试和验证 nil 检查消除优化功能的重要组成部分，它通过各种基准测试和单元测试确保了这个优化的正确性和性能。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/nilcheck_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"strconv"
	"testing"
)

func BenchmarkNilCheckDeep1(b *testing.B)     { benchmarkNilCheckDeep(b, 1) }
func BenchmarkNilCheckDeep10(b *testing.B)    { benchmarkNilCheckDeep(b, 10) }
func BenchmarkNilCheckDeep100(b *testing.B)   { benchmarkNilCheckDeep(b, 100) }
func BenchmarkNilCheckDeep1000(b *testing.B)  { benchmarkNilCheckDeep(b, 1000) }
func BenchmarkNilCheckDeep10000(b *testing.B) { benchmarkNilCheckDeep(b, 10000) }

// benchmarkNilCheckDeep is a stress test of nilcheckelim.
// It uses the worst possible input: A linear string of
// nil checks, none of which can be eliminated.
// Run with multiple depths to observe big-O behavior.
func benchmarkNilCheckDeep(b *testing.B, depth int) {
	c := testConfig(b)
	ptrType := c.config.Types.BytePtr

	var blocs []bloc
	blocs = append(blocs,
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("sb", OpSB, c.config.Types.Uintptr, 0, nil),
			Goto(blockn(0)),
		),
	)
	for i := 0; i < depth; i++ {
		blocs = append(blocs,
			Bloc(blockn(i),
				Valu(ptrn(i), OpAddr, ptrType, 0, nil, "sb"),
				Valu(booln(i), OpIsNonNil, c.config.Types.Bool, 0, nil, ptrn(i)),
				If(booln(i), blockn(i+1), "exit"),
			),
		)
	}
	blocs = append(blocs,
		Bloc(blockn(depth), Goto("exit")),
		Bloc("exit", Exit("mem")),
	)

	fun := c.Fun("entry", blocs...)

	CheckFunc(fun.f)
	b.SetBytes(int64(depth)) // helps for eyeballing linearity
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		nilcheckelim(fun.f)
	}
}

func blockn(n int) string { return "b" + strconv.Itoa(n) }
func ptrn(n int) string   { return "p" + strconv.Itoa(n) }
func booln(n int) string  { return "c" + strconv.Itoa(n) }

func isNilCheck(b *Block) bool {
	return b.Kind == BlockIf && b.Controls[0].Op == OpIsNonNil
}

// TestNilcheckSimple verifies that a second repeated nilcheck is removed.
func TestNilcheckSimple(t *testing.T) {
	c := testConfig(t)
	ptrType := c.config.Types.BytePtr
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("sb", OpSB, c.config.Types.Uintptr, 0, nil),
			Goto("checkPtr")),
		Bloc("checkPtr",
			Valu("ptr1", OpLoad, ptrType, 0, nil, "sb", "mem"),
			Valu("bool1", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool1", "secondCheck", "exit")),
		Bloc("secondCheck",
			Valu("bool2", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool2", "extra", "exit")),
		Bloc("extra",
			Goto("exit")),
		Bloc("exit",
			Exit("mem")))

	CheckFunc(fun.f)
	nilcheckelim(fun.f)

	// clean up the removed nil check
	fuse(fun.f, fuseTypePlain)
	deadcode(fun.f)

	CheckFunc(fun.f)
	for _, b := range fun.f.Blocks {
		if b == fun.blocks["secondCheck"] && isNilCheck(b) {
			t.Errorf("secondCheck was not eliminated")
		}
	}
}

// TestNilcheckDomOrder ensures that the nil check elimination isn't dependent
// on the order of the dominees.
func TestNilcheckDomOrder(t *testing.T) {
	c := testConfig(t)
	ptrType := c.config.Types.BytePtr
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("sb", OpSB, c.config.Types.Uintptr, 0, nil),
			Goto("checkPtr")),
		Bloc("checkPtr",
			Valu("ptr1", OpLoad, ptrType, 0, nil, "sb", "mem"),
			Valu("bool1", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool1", "secondCheck", "exit")),
		Bloc("exit",
			Exit("mem")),
		Bloc("secondCheck",
			Valu("bool2", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool2", "extra", "exit")),
		Bloc("extra",
			Goto("exit")))

	CheckFunc(fun.f)
	nilcheckelim(fun.f)

	// clean up the removed nil check
	fuse(fun.f, fuseTypePlain)
	deadcode(fun.f)

	CheckFunc(fun.f)
	for _, b := range fun.f.Blocks {
		if b == fun.blocks["secondCheck"] && isNilCheck(b) {
			t.Errorf("secondCheck was not eliminated")
		}
	}
}

// TestNilcheckAddr verifies that nilchecks of OpAddr constructed values are removed.
func TestNilcheckAddr(t *testing.T) {
	c := testConfig(t)
	ptrType := c.config.Types.BytePtr
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("sb", OpSB, c.config.Types.Uintptr, 0, nil),
			Goto("checkPtr")),
		Bloc("checkPtr",
			Valu("ptr1", OpAddr, ptrType, 0, nil, "sb"),
			Valu("bool1", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool1", "extra", "exit")),
		Bloc("extra",
			Goto("exit")),
		Bloc("exit",
			Exit("mem")))

	CheckFunc(fun.f)
	nilcheckelim(fun.f)

	// clean up the removed nil check
	fuse(fun.f, fuseTypePlain)
	deadcode(fun.f)

	CheckFunc(fun.f)
	for _, b := range fun.f.Blocks {
		if b == fun.blocks["checkPtr"] && isNilCheck(b) {
			t.Errorf("checkPtr was not eliminated")
		}
	}
}

// TestNilcheckAddPtr verifies that nilchecks of OpAddPtr constructed values are removed.
func TestNilcheckAddPtr(t *testing.T) {
	c := testConfig(t)
	ptrType := c.config.Types.BytePtr
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("sb", OpSB, c.config.Types.Uintptr, 0, nil),
			Goto("checkPtr")),
		Bloc("checkPtr",
			Valu("off", OpConst64, c.config.Types.Int64, 20, nil),
			Valu("ptr1", OpAddPtr, ptrType, 0, nil, "sb", "off"),
			Valu("bool1", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool1", "extra", "exit")),
		Bloc("extra",
			Goto("exit")),
		Bloc("exit",
			Exit("mem")))

	CheckFunc(fun.f)
	nilcheckelim(fun.f)

	// clean up the removed nil check
	fuse(fun.f, fuseTypePlain)
	deadcode(fun.f)

	CheckFunc(fun.f)
	for _, b := range fun.f.Blocks {
		if b == fun.blocks["checkPtr"] && isNilCheck(b) {
			t.Errorf("checkPtr was not eliminated")
		}
	}
}

// TestNilcheckPhi tests that nil checks of phis, for which all values are known to be
// non-nil are removed.
func TestNilcheckPhi(t *testing.T) {
	c := testConfig(t)
	ptrType := c.config.Types.BytePtr
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("sb", OpSB, c.config.Types.Uintptr, 0, nil),
			Valu("sp", OpSP, c.config.Types.Uintptr, 0, nil),
			Valu("baddr", OpLocalAddr, c.config.Types.Bool, 0, StringToAux("b"), "sp", "mem"),
			Valu("bool1", OpLoad, c.config.Types.Bool, 0, nil, "baddr", "mem"),
			If("bool1", "b1", "b2")),
		Bloc("b1",
			Valu("ptr1", OpAddr, ptrType, 0, nil, "sb"),
			Goto("checkPtr")),
		Bloc("b2",
			Valu("ptr2", OpAddr, ptrType, 0, nil, "sb"),
			Goto("checkPtr")),
		// both ptr1 and ptr2 are guaranteed non-nil here
		Bloc("checkPtr",
			Valu("phi", OpPhi, ptrType, 0, nil, "ptr1", "ptr2"),
			Valu("bool2", OpIsNonNil, c.config.Types.Bool, 0, nil, "phi"),
			If("bool2", "extra", "exit")),
		Bloc("extra",
			Goto("exit")),
		Bloc("exit",
			Exit("mem")))

	CheckFunc(fun.f)
	nilcheckelim(fun.f)

	// clean up the removed nil check
	fuse(fun.f, fuseTypePlain)
	deadcode(fun.f)

	CheckFunc(fun.f)
	for _, b := range fun.f.Blocks {
		if b == fun.blocks["checkPtr"] && isNilCheck(b) {
			t.Errorf("checkPtr was not eliminated")
		}
	}
}

// TestNilcheckKeepRemove verifies that duplicate checks of the same pointer
// are removed, but checks of different pointers are not.
func TestNilcheckKeepRemove(t *testing.T) {
	c := testConfig(t)
	ptrType := c.config.Types.BytePtr
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("sb", OpSB, c.config.Types.Uintptr, 0, nil),
			Goto("checkPtr")),
		Bloc("checkPtr",
			Valu("ptr1", OpLoad, ptrType, 0, nil, "sb", "mem"),
			Valu("bool1", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool1", "differentCheck", "exit")),
		Bloc("differentCheck",
			Valu("ptr2", OpLoad, ptrType, 0, nil, "sb", "mem"),
			Valu("bool2", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr2"),
			If("bool2", "secondCheck", "exit")),
		Bloc("secondCheck",
			Valu("bool3", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool3", "extra", "exit")),
		Bloc("extra",
			Goto("exit")),
		Bloc("exit",
			Exit("mem")))

	CheckFunc(fun.f)
	nilcheckelim(fun.f)

	// clean up the removed nil check
	fuse(fun.f, fuseTypePlain)
	deadcode(fun.f)

	CheckFunc(fun.f)
	foundDifferentCheck := false
	for _, b := range fun.f.Blocks {
		if b == fun.blocks["secondCheck"] && isNilCheck(b) {
			t.Errorf("secondCheck was not eliminated")
		}
		if b == fun.blocks["differentCheck"] && isNilCheck(b) {
			foundDifferentCheck = true
		}
	}
	if !foundDifferentCheck {
		t.Errorf("removed differentCheck, but shouldn't have")
	}
}

// TestNilcheckInFalseBranch tests that nil checks in the false branch of a nilcheck
// block are *not* removed.
func TestNilcheckInFalseBranch(t *testing.T) {
	c := testConfig(t)
	ptrType := c.config.Types.BytePtr
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("sb", OpSB, c.config.Types.Uintptr, 0, nil),
			Goto("checkPtr")),
		Bloc("checkPtr",
			Valu("ptr1", OpLoad, ptrType, 0, nil, "sb", "mem"),
			Valu("bool1", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool1", "extra", "secondCheck")),
		Bloc("secondCheck",
			Valu("bool2", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool2", "extra", "thirdCheck")),
		Bloc("thirdCheck",
			Valu("bool3", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool3", "extra", "exit")),
		Bloc("extra",
			Goto("exit")),
		Bloc("exit",
			Exit("mem")))

	CheckFunc(fun.f)
	nilcheckelim(fun.f)

	// clean up the removed nil check
	fuse(fun.f, fuseTypePlain)
	deadcode(fun.f)

	CheckFunc(fun.f)
	foundSecondCheck := false
	foundThirdCheck := false
	for _, b := range fun.f.Blocks {
		if b == fun.blocks["secondCheck"] && isNilCheck(b) {
			foundSecondCheck = true
		}
		if b == fun.blocks["thirdCheck"] && isNilCheck(b) {
			foundThirdCheck = true
		}
	}
	if !foundSecondCheck {
		t.Errorf("removed secondCheck, but shouldn't have [false branch]")
	}
	if !foundThirdCheck {
		t.Errorf("removed thirdCheck, but shouldn't have [false branch]")
	}
}

// TestNilcheckUser verifies that a user nil check that dominates a generated nil check
// wil remove the generated nil check.
func TestNilcheckUser(t *testing.T) {
	c := testConfig(t)
	ptrType := c.config.Types.BytePtr
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("sb", OpSB, c.config.Types.Uintptr, 0, nil),
			Goto("checkPtr")),
		Bloc("checkPtr",
			Valu("ptr1", OpLoad, ptrType, 0, nil, "sb", "mem"),
			Valu("nilptr", OpConstNil, ptrType, 0, nil),
			Valu("bool1", OpNeqPtr, c.config.Types.Bool, 0, nil, "ptr1", "nilptr"),
			If("bool1", "secondCheck", "exit")),
		Bloc("secondCheck",
			Valu("bool2", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool2", "extra", "exit")),
		Bloc("extra",
			Goto("exit")),
		Bloc("exit",
			Exit("mem")))

	CheckFunc(fun.f)
	// we need the opt here to rewrite the user nilcheck
	opt(fun.f)
	nilcheckelim(fun.f)

	// clean up the removed nil check
	fuse(fun.f, fuseTypePlain)
	deadcode(fun.f)

	CheckFunc(fun.f)
	for _, b := range fun.f.Blocks {
		if b == fun.blocks["secondCheck"] && isNilCheck(b) {
			t.Errorf("secondCheck was not eliminated")
		}
	}
}

// TestNilcheckBug reproduces a bug in nilcheckelim found by compiling math/big
func TestNilcheckBug(t *testing.T) {
	c := testConfig(t)
	ptrType := c.config.Types.BytePtr
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Valu("sb", OpSB, c.config.Types.Uintptr, 0, nil),
			Goto("checkPtr")),
		Bloc("checkPtr",
			Valu("ptr1", OpLoad, ptrType, 0, nil, "sb", "mem"),
			Valu("nilptr", OpConstNil, ptrType, 0, nil),
			Valu("bool1", OpNeqPtr, c.config.Types.Bool, 0, nil, "ptr1", "nilptr"),
			If("bool1", "secondCheck", "couldBeNil")),
		Bloc("couldBeNil",
			Goto("secondCheck")),
		Bloc("secondCheck",
			Valu("bool2", OpIsNonNil, c.config.Types.Bool, 0, nil, "ptr1"),
			If("bool2", "extra", "exit")),
		Bloc("extra",
			// prevent fuse from eliminating this block
			Valu("store", OpStore, types.TypeMem, 0, ptrType, "ptr1", "nilptr", "mem"),
			Goto("exit")),
		Bloc("exit",
			Valu("phi", OpPhi, types.TypeMem, 0, nil, "mem", "store"),
			Exit("phi")))

	CheckFunc(fun.f)
	// we need the opt here to rewrite the user nilcheck
	opt(fun.f)
	nilcheckelim(fun.f)

	// clean up the removed nil check
	fuse(fun.f, fuseTypePlain)
	deadcode(fun.f)

	CheckFunc(fun.f)
	foundSecondCheck := false
	for _, b := range fun.f.Blocks {
		if b == fun.blocks["secondCheck"] && isNilCheck(b) {
			foundSecondCheck = true
		}
	}
	if !foundSecondCheck {
		t.Errorf("secondCheck was eliminated, but shouldn't have")
	}
}
```