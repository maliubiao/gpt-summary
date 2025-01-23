Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Understanding the Goal:**

The core request is to understand the *purpose* and *functionality* of the provided Go code. It's explicitly stated that it's a part of the `go/src/cmd/compile/internal/ssa/func_test.go` file. This immediately tells us it's related to testing the Static Single Assignment (SSA) form within the Go compiler.

**2. Initial Code Scan and Keyword Recognition:**

I'd start by quickly scanning the code for recurring patterns and keywords. Key observations:

* **`Fun`, `Bloc`, `Valu`, `Goto`, `If`, `Exit`:** These look like custom helper functions for defining SSA function structures. The example comment at the top reinforces this idea.
* **`Func`, `Block`, `Value`:** These are likely the core SSA data structures being tested.
* **`Equiv`:** This function compares two `Func` objects for equivalence, suggesting testing of SSA transformations or construction.
* **`testConfig`:**  This likely initializes the compiler configuration necessary for creating SSA functions.
* **`t *testing.T`:** This confirms it's part of the standard Go testing framework.
* **`Op`, `types.Type`, `Aux`, `AuxInt`:** These are likely components of the `Value` structure in SSA.
* **`opcodeMap`, `checkOpcodeCounts`:** These functions suggest testing the number of specific operations in a generated SSA function.

**3. Focusing on the Core Data Structures and Helpers:**

The comment at the beginning is crucial. It clearly illustrates how the helper functions (`Fun`, `Bloc`, `Valu`, etc.) are used to represent a simple control flow graph (CFG) and the values within it. This allows me to infer the purpose of each helper:

* **`Fun`:**  Creates a `Func` object, the top-level representation of an SSA function. It takes an entry block name and a series of `Bloc` definitions.
* **`Bloc`:** Defines a basic block within the SSA function. It takes a name and a list of entries, which can be `Valu` or control flow instructions (`Goto`, `If`, `Exit`).
* **`Valu`:** Defines a value (an SSA instruction) within a block. It takes a name, opcode, type, auxiliary information, and arguments (references to other values).
* **`Goto`, `If`, `Exit`, `Eq`:** These define the control flow transitions between blocks.

**4. Analyzing the `Equiv` Function:**

This function is essential for verifying the correctness of SSA transformations. I'd analyze its logic step by step:

* **`valcor` and `blkcor`:** These maps are used to track the correspondence between values and blocks in the two `Func` objects being compared. This is a standard technique for graph isomorphism checking.
* **Recursive `checkVal` and `checkBlk`:** The recursive nature handles the potentially complex structure of the CFG and the dependencies between values.
* **Comparison Logic:**  It compares the `Op`, `Type`, `AuxInt`, `Aux`, and arguments of values, and the `Kind` and successors/predecessors of blocks. The crucial point is that it's a *structural* equivalence check.

**5. Examining the Test Cases:**

The `TestArgs` and `TestEquiv` functions provide concrete examples of how the helper functions and the `Equiv` function are used.

* **`TestArgs`:** Shows how to create a simple function and access the arguments of a value.
* **`TestEquiv`:**  Provides positive and negative test cases for the `Equiv` function, illustrating scenarios where functions are considered equivalent (even with block order changes) and where they are different (due to different structure, value order, or attributes).

**6. Understanding `TestConstCache`:**

This test focuses on the internal caching mechanism of the `Func` object for constant values. It verifies that freeing and then re-requesting constants with different `AuxInt` values produces the correct results.

**7. Inferring the Overall Purpose:**

Based on the elements analyzed, the overall purpose of this code is clearly:

* **To provide a convenient way to construct and represent SSA functions for testing purposes.**  The helper functions significantly simplify the manual creation of complex SSA graphs.
* **To provide a mechanism for comparing SSA functions for structural equivalence.** This is crucial for verifying that compiler passes transform the SSA form correctly without altering its essential meaning.
* **To test specific aspects of the SSA implementation**, such as constant caching.

**8. Addressing Specific Questions:**

With a good understanding of the code, I can now address the specific questions in the prompt:

* **Functionality:** List the key functions and their roles.
* **Go Feature Implementation:** Infer it's about testing the SSA representation within the Go compiler and give a code example using the helper functions.
* **Code Inference (Input/Output):**  Use the `TestEquiv` examples to illustrate how the `Equiv` function works with different inputs and what the expected output (true/false) is.
* **Command-line Arguments:**  This file is a testing utility, not a standalone executable, so it doesn't directly process command-line arguments. I would clarify this.
* **Common Mistakes:** Analyze the test cases to identify potential pitfalls for users of this testing framework, such as assuming value or block order matters for equivalence (which the `Equiv` function tries to handle, but the user needs to be aware of the constraints).

This systematic approach, starting with high-level understanding and progressively drilling down into details, allows for a comprehensive analysis of the provided Go code snippet. The key is to recognize the testing context and the purpose of the custom helper functions.
这个 Go 语言文件 `func_test.go` 的主要功能是为 Go 编译器内部的 SSA (Static Single Assignment) 中间表示提供了一套 **用于测试的实用工具函数**。它简化了在测试中创建和比较 SSA 函数的过程。

以下是其主要功能的详细列举：

1. **定义 SSA 函数的便捷方式:**
   - 提供了 `Fun` 函数，允许用户通过链式调用 `Bloc`、`Valu`、`Goto`、`If`、`Exit` 等函数来声明 SSA 函数的结构。这比直接操作底层的 `Block` 和 `Value` 结构更加简洁易懂。
   - `Bloc` 用于定义基本块，包含一系列的 `Valu` (值) 以及控制流指令。
   - `Valu` 用于定义基本块内的值（操作），可以指定操作码 (`Op`)、类型 (`types.Type`)、辅助整数 (`auxint`)、辅助信息 (`Aux`) 和参数。
   - `Goto`、`If`、`Exit` 等函数用于定义块的控制流，例如无条件跳转、条件跳转和退出。

2. **比较两个 SSA 函数的等价性:**
   - 提供了 `Equiv` 函数，用于比较两个 `Func` 对象是否在结构和值上等价。
   - `Equiv` 会递归地比较两个函数的控制流图 (CFG) 是否同构，以及对应的块和值是否具有相同的操作、类型、辅助信息和参数。

3. **辅助构建 `Value` 的工具:**
   - 提供了 `AuxCallLSym` 函数，用于创建一个 `AuxCall` 对象，该对象可以作为静态调用指令的辅助信息。

**它是什么 Go 语言功能的实现？**

这个文件本身并不是直接实现某个 Go 语言功能，而是为了 **测试 Go 编译器内部的 SSA 表示** 而存在的。SSA 是编译器在进行代码优化时使用的一种中间表示形式。

**Go 代码举例说明:**

假设我们要测试一个简单的加法函数的 SSA 表示。使用 `func_test.go` 提供的工具，可以这样定义：

```go
package ssa

import (
	"cmd/compile/internal/types"
	"testing"
)

func TestSimpleAdd(t *testing.T) {
	c := testConfig(t)
	intType := c.config.Types.Int64 // 假设是 int64 类型

	expected := c.Fun("entry",
		Bloc("entry",
			Valu("a", OpArg, intType, 0, nil),
			Valu("b", OpArg, intType, 0, nil),
			Valu("sum", OpAdd64, intType, 0, nil, "a", "b"),
			Goto("exit")),
		Bloc("exit",
			Valu("mem", OpInitMem, c.config.Types.Mem, 0, nil),
			Valu("ret", OpRet, types.TypeInvalid, 0, nil, "mem", "sum")),
	)

	// 假设我们有一个函数 `compileAdd` 可以生成加法函数的 SSA
	// actual := compileAdd(...)

	// 使用 Equiv 函数比较期望的 SSA 和实际生成的 SSA
	// if !Equiv(expected.f, actual) {
	// 	t.Errorf("SSA for add function is incorrect")
	// }
}
```

**假设的输入与输出（针对 `Equiv` 函数）：**

**假设输入 1 (两个等价的函数):**

```go
func1 := c.Fun("entry",
	Bloc("entry",
		Valu("x", OpConst64, c.config.Types.Int64, 10, nil),
		Goto("exit")),
	Bloc("exit",
		Valu("mem", OpInitMem, c.config.Types.Mem, 0, nil),
		Exit("mem")),
)

func2 := c.Fun("start", // entry block name 可以不同
	Bloc("start",
		Valu("y", OpConst64, c.config.Types.Int64, 10, nil), // value name 可以不同
		Goto("end")),
	Bloc("end",
		Valu("m", OpInitMem, c.config.Types.Mem, 0, nil), // value name 可以不同
		Exit("m")),
)
```

**输出:** `Equiv(func1.f, func2.f)` 将返回 `true`。虽然块名和值名不同，但它们的结构和操作是相同的。

**假设输入 2 (两个不等的函数):**

```go
func3 := c.Fun("entry",
	Bloc("entry",
		Valu("x", OpConst64, c.config.Types.Int64, 10, nil),
		Goto("exit")),
	Bloc("exit",
		Valu("mem", OpInitMem, c.config.Types.Mem, 0, nil),
		Exit("mem")),
)

func4 := c.Fun("entry",
	Bloc("entry",
		Valu("x", OpConst64, c.config.Types.Int32, 10, nil), // 类型不同
		Goto("exit")),
	Bloc("exit",
		Valu("mem", OpInitMem, c.config.Types.Mem, 0, nil),
		Exit("mem")),
)
```

**输出:** `Equiv(func3.f, func4.f)` 将返回 `false`，因为 `x` 值的类型不同。

**命令行参数的具体处理:**

这个文件本身不是一个可执行程序，它是一个测试文件，用于在 Go 的测试框架下运行。因此，它 **不直接处理命令行参数**。

**使用者易犯错的点:**

1. **假设值或块的顺序是固定的:** `Equiv` 函数目前的一个限制是，它要求值和前驱节点的顺序相同。这意味着即使两个函数在逻辑上是等价的，如果其内部的值或前驱节点的顺序不同，`Equiv` 可能会返回 `false`。作者在代码注释中也提到了这一点，并计划在未来改进。

   **错误示例:**

   ```go
   func5 := c.Fun("entry",
       Bloc("entry",
           Valu("a", OpConst64, c.config.Types.Int64, 1, nil),
           Valu("b", OpConst64, c.config.Types.Int64, 2, nil),
           Goto("exit")),
       Bloc("exit",
           Valu("mem", OpInitMem, c.config.Types.Mem, 0, nil),
           Exit("mem")),
   )

   func6 := c.Fun("entry",
       Bloc("entry",
           Valu("b", OpConst64, c.config.Types.Int64, 2, nil), // 顺序不同
           Valu("a", OpConst64, c.config.Types.Int64, 1, nil),
           Goto("exit")),
       Bloc("exit",
           Valu("mem", OpInitMem, c.config.Types.Mem, 0, nil),
           Exit("mem")),
   )

   // 按照目前的 Equiv 实现，这可能会返回 false，即使逻辑上等价
   // if !Equiv(func5.f, func6.f) { ... }
   ```

2. **忘记指定所有必要的参数或控制流:** 在使用 `Fun`、`Bloc` 和 `Valu` 构建 SSA 函数时，容易忘记为 `Valu` 指定所有的参数，或者忘记在 `Bloc` 中定义控制流指令（`Goto`、`If`、`Exit`）。这会导致 `Fun` 函数在内部报错。

   **错误示例:**

   ```go
   // 忘记指定 "sum" 值的参数
   badFun := c.Fun("entry",
       Bloc("entry",
           Valu("a", OpConst64, c.config.Types.Int64, 1, nil),
           Valu("b", OpConst64, c.config.Types.Int64, 2, nil),
           Valu("sum", OpAdd64, c.config.Types.Int64, 0, nil), // 缺少参数
           // 缺少控制流指令
       ),
   )
   ```

   在上面的例子中，`Valu("sum", ...)` 缺少了需要相加的两个值 `"a"` 和 `"b"` 作为参数，并且 `Bloc("entry", ...)` 中缺少了控制流指令，会导致 `Fun` 函数执行失败。

总而言之，`func_test.go` 是 Go 编译器 SSA 测试框架的重要组成部分，它提供了一组方便的工具来定义、构建和比较 SSA 函数，从而帮助开发者验证编译器优化和转换的正确性。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/func_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// This file contains some utility functions to help define Funcs for testing.
// As an example, the following func
//
//   b1:
//     v1 = InitMem <mem>
//     Plain -> b2
//   b2:
//     Exit v1
//   b3:
//     v2 = Const <bool> [true]
//     If v2 -> b3 b2
//
// can be defined as
//
//   fun := Fun("entry",
//       Bloc("entry",
//           Valu("mem", OpInitMem, types.TypeMem, 0, nil),
//           Goto("exit")),
//       Bloc("exit",
//           Exit("mem")),
//       Bloc("deadblock",
//          Valu("deadval", OpConstBool, c.config.Types.Bool, 0, true),
//          If("deadval", "deadblock", "exit")))
//
// and the Blocks or Values used in the Func can be accessed
// like this:
//   fun.blocks["entry"] or fun.values["deadval"]

package ssa

// TODO(matloob): Choose better names for Fun, Bloc, Goto, etc.
// TODO(matloob): Write a parser for the Func disassembly. Maybe
// the parser can be used instead of Fun.

import (
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/src"
	"fmt"
	"reflect"
	"testing"
)

// Compare two Funcs for equivalence. Their CFGs must be isomorphic,
// and their values must correspond.
// Requires that values and predecessors are in the same order, even
// though Funcs could be equivalent when they are not.
// TODO(matloob): Allow values and predecessors to be in different
// orders if the CFG are otherwise equivalent.
func Equiv(f, g *Func) bool {
	valcor := make(map[*Value]*Value)
	var checkVal func(fv, gv *Value) bool
	checkVal = func(fv, gv *Value) bool {
		if fv == nil && gv == nil {
			return true
		}
		if valcor[fv] == nil && valcor[gv] == nil {
			valcor[fv] = gv
			valcor[gv] = fv
			// Ignore ids. Ops and Types are compared for equality.
			// TODO(matloob): Make sure types are canonical and can
			// be compared for equality.
			if fv.Op != gv.Op || fv.Type != gv.Type || fv.AuxInt != gv.AuxInt {
				return false
			}
			if !reflect.DeepEqual(fv.Aux, gv.Aux) {
				// This makes the assumption that aux values can be compared
				// using DeepEqual.
				// TODO(matloob): Aux values may be *gc.Sym pointers in the near
				// future. Make sure they are canonical.
				return false
			}
			if len(fv.Args) != len(gv.Args) {
				return false
			}
			for i := range fv.Args {
				if !checkVal(fv.Args[i], gv.Args[i]) {
					return false
				}
			}
		}
		return valcor[fv] == gv && valcor[gv] == fv
	}
	blkcor := make(map[*Block]*Block)
	var checkBlk func(fb, gb *Block) bool
	checkBlk = func(fb, gb *Block) bool {
		if blkcor[fb] == nil && blkcor[gb] == nil {
			blkcor[fb] = gb
			blkcor[gb] = fb
			// ignore ids
			if fb.Kind != gb.Kind {
				return false
			}
			if len(fb.Values) != len(gb.Values) {
				return false
			}
			for i := range fb.Values {
				if !checkVal(fb.Values[i], gb.Values[i]) {
					return false
				}
			}
			if len(fb.Succs) != len(gb.Succs) {
				return false
			}
			for i := range fb.Succs {
				if !checkBlk(fb.Succs[i].b, gb.Succs[i].b) {
					return false
				}
			}
			if len(fb.Preds) != len(gb.Preds) {
				return false
			}
			for i := range fb.Preds {
				if !checkBlk(fb.Preds[i].b, gb.Preds[i].b) {
					return false
				}
			}
			return true

		}
		return blkcor[fb] == gb && blkcor[gb] == fb
	}

	return checkBlk(f.Entry, g.Entry)
}

// fun is the return type of Fun. It contains the created func
// itself as well as indexes from block and value names into the
// corresponding Blocks and Values.
type fun struct {
	f      *Func
	blocks map[string]*Block
	values map[string]*Value
}

var emptyPass pass = pass{
	name: "empty pass",
}

// AuxCallLSym returns an AuxCall initialized with an LSym that should pass "check"
// as the Aux of a static call.
func AuxCallLSym(name string) *AuxCall {
	return &AuxCall{Fn: &obj.LSym{}}
}

// Fun takes the name of an entry bloc and a series of Bloc calls, and
// returns a fun containing the composed Func. entry must be a name
// supplied to one of the Bloc functions. Each of the bloc names and
// valu names should be unique across the Fun.
func (c *Conf) Fun(entry string, blocs ...bloc) fun {
	// TODO: Either mark some SSA tests as t.Parallel,
	// or set up a shared Cache and Reset it between tests.
	// But not both.
	f := c.config.NewFunc(c.Frontend(), new(Cache))
	f.pass = &emptyPass
	f.cachedLineStarts = newXposmap(map[int]lineRange{0: {0, 100}, 1: {0, 100}, 2: {0, 100}, 3: {0, 100}, 4: {0, 100}})

	blocks := make(map[string]*Block)
	values := make(map[string]*Value)
	// Create all the blocks and values.
	for _, bloc := range blocs {
		b := f.NewBlock(bloc.control.kind)
		blocks[bloc.name] = b
		for _, valu := range bloc.valus {
			// args are filled in the second pass.
			values[valu.name] = b.NewValue0IA(src.NoXPos, valu.op, valu.t, valu.auxint, valu.aux)
		}
	}
	// Connect the blocks together and specify control values.
	f.Entry = blocks[entry]
	for _, bloc := range blocs {
		b := blocks[bloc.name]
		c := bloc.control
		// Specify control values.
		if c.control != "" {
			cval, ok := values[c.control]
			if !ok {
				f.Fatalf("control value for block %s missing", bloc.name)
			}
			b.SetControl(cval)
		}
		// Fill in args.
		for _, valu := range bloc.valus {
			v := values[valu.name]
			for _, arg := range valu.args {
				a, ok := values[arg]
				if !ok {
					b.Fatalf("arg %s missing for value %s in block %s",
						arg, valu.name, bloc.name)
				}
				v.AddArg(a)
			}
		}
		// Connect to successors.
		for _, succ := range c.succs {
			b.AddEdgeTo(blocks[succ])
		}
	}
	return fun{f, blocks, values}
}

// Bloc defines a block for Fun. The bloc name should be unique
// across the containing Fun. entries should consist of calls to valu,
// as well as one call to Goto, If, or Exit to specify the block kind.
func Bloc(name string, entries ...interface{}) bloc {
	b := bloc{}
	b.name = name
	seenCtrl := false
	for _, e := range entries {
		switch v := e.(type) {
		case ctrl:
			// there should be exactly one Ctrl entry.
			if seenCtrl {
				panic(fmt.Sprintf("already seen control for block %s", name))
			}
			b.control = v
			seenCtrl = true
		case valu:
			b.valus = append(b.valus, v)
		}
	}
	if !seenCtrl {
		panic(fmt.Sprintf("block %s doesn't have control", b.name))
	}
	return b
}

// Valu defines a value in a block.
func Valu(name string, op Op, t *types.Type, auxint int64, aux Aux, args ...string) valu {
	return valu{name, op, t, auxint, aux, args}
}

// Goto specifies that this is a BlockPlain and names the single successor.
// TODO(matloob): choose a better name.
func Goto(succ string) ctrl {
	return ctrl{BlockPlain, "", []string{succ}}
}

// If specifies a BlockIf.
func If(cond, sub, alt string) ctrl {
	return ctrl{BlockIf, cond, []string{sub, alt}}
}

// Exit specifies a BlockExit.
func Exit(arg string) ctrl {
	return ctrl{BlockExit, arg, []string{}}
}

// Eq specifies a BlockAMD64EQ.
func Eq(cond, sub, alt string) ctrl {
	return ctrl{BlockAMD64EQ, cond, []string{sub, alt}}
}

// bloc, ctrl, and valu are internal structures used by Bloc, Valu, Goto,
// If, and Exit to help define blocks.

type bloc struct {
	name    string
	control ctrl
	valus   []valu
}

type ctrl struct {
	kind    BlockKind
	control string
	succs   []string
}

type valu struct {
	name   string
	op     Op
	t      *types.Type
	auxint int64
	aux    Aux
	args   []string
}

func TestArgs(t *testing.T) {
	c := testConfig(t)
	fun := c.Fun("entry",
		Bloc("entry",
			Valu("a", OpConst64, c.config.Types.Int64, 14, nil),
			Valu("b", OpConst64, c.config.Types.Int64, 26, nil),
			Valu("sum", OpAdd64, c.config.Types.Int64, 0, nil, "a", "b"),
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Goto("exit")),
		Bloc("exit",
			Exit("mem")))
	sum := fun.values["sum"]
	for i, name := range []string{"a", "b"} {
		if sum.Args[i] != fun.values[name] {
			t.Errorf("arg %d for sum is incorrect: want %s, got %s",
				i, sum.Args[i], fun.values[name])
		}
	}
}

func TestEquiv(t *testing.T) {
	cfg := testConfig(t)
	equivalentCases := []struct{ f, g fun }{
		// simple case
		{
			cfg.Fun("entry",
				Bloc("entry",
					Valu("a", OpConst64, cfg.config.Types.Int64, 14, nil),
					Valu("b", OpConst64, cfg.config.Types.Int64, 26, nil),
					Valu("sum", OpAdd64, cfg.config.Types.Int64, 0, nil, "a", "b"),
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Goto("exit")),
				Bloc("exit",
					Exit("mem"))),
			cfg.Fun("entry",
				Bloc("entry",
					Valu("a", OpConst64, cfg.config.Types.Int64, 14, nil),
					Valu("b", OpConst64, cfg.config.Types.Int64, 26, nil),
					Valu("sum", OpAdd64, cfg.config.Types.Int64, 0, nil, "a", "b"),
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Goto("exit")),
				Bloc("exit",
					Exit("mem"))),
		},
		// block order changed
		{
			cfg.Fun("entry",
				Bloc("entry",
					Valu("a", OpConst64, cfg.config.Types.Int64, 14, nil),
					Valu("b", OpConst64, cfg.config.Types.Int64, 26, nil),
					Valu("sum", OpAdd64, cfg.config.Types.Int64, 0, nil, "a", "b"),
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Goto("exit")),
				Bloc("exit",
					Exit("mem"))),
			cfg.Fun("entry",
				Bloc("exit",
					Exit("mem")),
				Bloc("entry",
					Valu("a", OpConst64, cfg.config.Types.Int64, 14, nil),
					Valu("b", OpConst64, cfg.config.Types.Int64, 26, nil),
					Valu("sum", OpAdd64, cfg.config.Types.Int64, 0, nil, "a", "b"),
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Goto("exit"))),
		},
	}
	for _, c := range equivalentCases {
		if !Equiv(c.f.f, c.g.f) {
			t.Error("expected equivalence. Func definitions:")
			t.Error(c.f.f)
			t.Error(c.g.f)
		}
	}

	differentCases := []struct{ f, g fun }{
		// different shape
		{
			cfg.Fun("entry",
				Bloc("entry",
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Goto("exit")),
				Bloc("exit",
					Exit("mem"))),
			cfg.Fun("entry",
				Bloc("entry",
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Exit("mem"))),
		},
		// value order changed
		{
			cfg.Fun("entry",
				Bloc("entry",
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Valu("b", OpConst64, cfg.config.Types.Int64, 26, nil),
					Valu("a", OpConst64, cfg.config.Types.Int64, 14, nil),
					Exit("mem"))),
			cfg.Fun("entry",
				Bloc("entry",
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Valu("a", OpConst64, cfg.config.Types.Int64, 14, nil),
					Valu("b", OpConst64, cfg.config.Types.Int64, 26, nil),
					Exit("mem"))),
		},
		// value auxint different
		{
			cfg.Fun("entry",
				Bloc("entry",
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Valu("a", OpConst64, cfg.config.Types.Int64, 14, nil),
					Exit("mem"))),
			cfg.Fun("entry",
				Bloc("entry",
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Valu("a", OpConst64, cfg.config.Types.Int64, 26, nil),
					Exit("mem"))),
		},
		// value aux different
		{
			cfg.Fun("entry",
				Bloc("entry",
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Valu("a", OpConstString, cfg.config.Types.String, 0, StringToAux("foo")),
					Exit("mem"))),
			cfg.Fun("entry",
				Bloc("entry",
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Valu("a", OpConstString, cfg.config.Types.String, 0, StringToAux("bar")),
					Exit("mem"))),
		},
		// value args different
		{
			cfg.Fun("entry",
				Bloc("entry",
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Valu("a", OpConst64, cfg.config.Types.Int64, 14, nil),
					Valu("b", OpConst64, cfg.config.Types.Int64, 26, nil),
					Valu("sum", OpAdd64, cfg.config.Types.Int64, 0, nil, "a", "b"),
					Exit("mem"))),
			cfg.Fun("entry",
				Bloc("entry",
					Valu("mem", OpInitMem, types.TypeMem, 0, nil),
					Valu("a", OpConst64, cfg.config.Types.Int64, 0, nil),
					Valu("b", OpConst64, cfg.config.Types.Int64, 14, nil),
					Valu("sum", OpAdd64, cfg.config.Types.Int64, 0, nil, "b", "a"),
					Exit("mem"))),
		},
	}
	for _, c := range differentCases {
		if Equiv(c.f.f, c.g.f) {
			t.Error("expected difference. Func definitions:")
			t.Error(c.f.f)
			t.Error(c.g.f)
		}
	}
}

// TestConstCache ensures that the cache will not return
// reused free'd values with a non-matching AuxInt
func TestConstCache(t *testing.T) {
	c := testConfig(t)
	f := c.Fun("entry",
		Bloc("entry",
			Valu("mem", OpInitMem, types.TypeMem, 0, nil),
			Exit("mem")))
	v1 := f.f.ConstBool(c.config.Types.Bool, false)
	v2 := f.f.ConstBool(c.config.Types.Bool, true)
	f.f.freeValue(v1)
	f.f.freeValue(v2)
	v3 := f.f.ConstBool(c.config.Types.Bool, false)
	v4 := f.f.ConstBool(c.config.Types.Bool, true)
	if v3.AuxInt != 0 {
		t.Errorf("expected %s to have auxint of 0\n", v3.LongString())
	}
	if v4.AuxInt != 1 {
		t.Errorf("expected %s to have auxint of 1\n", v4.LongString())
	}

}

// opcodeMap returns a map from opcode to the number of times that opcode
// appears in the function.
func opcodeMap(f *Func) map[Op]int {
	m := map[Op]int{}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			m[v.Op]++
		}
	}
	return m
}

// opcodeCounts checks that the number of opcodes listed in m agree with the
// number of opcodes that appear in the function.
func checkOpcodeCounts(t *testing.T, f *Func, m map[Op]int) {
	n := opcodeMap(f)
	for op, cnt := range m {
		if n[op] != cnt {
			t.Errorf("%s appears %d times, want %d times", op, n[op], cnt)
		}
	}
}
```