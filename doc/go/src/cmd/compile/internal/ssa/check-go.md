Response: Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understand the Goal:** The request asks for the functionalities of the `check.go` file within the Go compiler's SSA (Static Single Assignment) package. Specifically, it wants to know what invariants this code checks and, if possible, infer the larger Go feature it relates to. It also asks for code examples, command-line arguments (if applicable), and common mistakes.

2. **Initial Scan and Keywords:**  Quickly reading through the code reveals a function named `checkFunc`. The comments within this function use terms like "invariants," "Fatalf," "block," "value," "pred," "succ," "control," "type," and "args."  These keywords strongly suggest this code is performing some kind of validation or sanity checking on the SSA representation of a Go function.

3. **Focus on `checkFunc`:**  Since `checkFunc` is the core of the provided snippet, the next step is a more detailed examination of its internal logic.

4. **Identify Data Structures:** The function takes a `*Func` as input, implying it operates on a function's SSA representation. It also initializes `blockMark` and `valueMark` which are boolean slices. These are likely used to detect duplicate blocks or values.

5. **Analyze Block Checks:** The code iterates through `f.Blocks`. Inside the loop, it performs several checks on each block (`b`):
    * **Uniqueness:** `blockMark` is used to ensure no block appears twice.
    * **Function Association:** `b.Func == f` confirms the block belongs to the current function.
    * **Cross-linking:**  Checks `b.Preds` and `b.Succs` to ensure predecessor and successor relationships are correctly mirrored.
    * **Block Kind Specific Checks:** The `switch b.Kind` statement handles different types of blocks (e.g., `BlockExit`, `BlockRet`, `BlockIf`). Each case enforces specific rules about the number of successors and the presence/type of control values. This is a crucial part for understanding the different control flow constructs in SSA.

6. **Analyze Value Checks:** Inside the block loop, there's another loop iterating through `b.Values`. This section performs checks on individual SSA values (`v`):
    * **Argument Count:**  Compares `len(v.Args)` with the expected count from `opcodeTable`.
    * **Auxiliary Values:**  The complex `switch opcodeTable[v.Op].auxType` block deals with checking the validity of auxiliary data associated with an operation. This highlights the importance of auxiliary information in SSA.
    * **Argument Validity:** Ensures arguments are not nil and that memory arguments are placed correctly.
    * **Uniqueness:** `valueMark` prevents duplicate values.
    * **Block Association:** `v.Block == b` verifies the value belongs to the correct block.
    * **Phi Node Consistency:** Checks if the number of arguments for `OpPhi` matches the number of predecessors of the block.
    * **Specific Opcode Checks:**  Handles special cases for opcodes like `OpAddr`, `OpLocalAddr`, `OpNilCheck`, etc. This gives clues about how specific operations are represented in SSA.
    * **Type Checking:** Enforces type constraints based on the opcode.

7. **Post-Block/Value Checks:** After the loops, the code performs checks that span across blocks and values:
    * **Reachability:** Ensures all referenced blocks and values are actually part of the function.
    * **Entry Block:** Verifies the entry block has no predecessors.
    * **Dominance:** Checks if arguments of a value and control values dominate the block where the value resides (except during register allocation). This relates to the fundamental concept of dominance in control flow graphs.
    * **Loop Construction:** Verifies the structure of loops in the SSA graph.
    * **Use Counts:** Ensures the `Uses` field of each value is consistent with the actual number of times it's used.

8. **Memory Checks (`memCheck`):**  This separate function focuses specifically on memory-related invariants:
    * **Tuple Memory Placement:** Checks if memory types in tuples are in the correct position.
    * **Single Live Memory (with limitations):**  Tries to ensure only one memory value is live at any point in the code (with caveats about memory copies and unused memory ops). This is important for reasoning about memory flow.
    * **Phi Node Consistency (Memory):** Verifies that memory phi nodes correctly merge incoming memory states.
    * **Phi Node Placement (after scheduling):** Enforces that phi nodes appear at the beginning of a block after scheduling.

9. **Inferring the Go Feature:** Based on the checks being performed, it's clear this code is part of the Go compiler's intermediate representation (SSA) generation and optimization process. The checks ensure the SSA form is well-formed and consistent. While it doesn't directly implement a specific *user-facing* Go feature, it's crucial for the correct compilation of *all* Go code.

10. **Generating Code Examples:** To illustrate the checks, think about common situations where these invariants might be violated. For instance, a block with the wrong number of successors would break control flow. A value with a mismatched argument count would lead to incorrect operation execution. Constructing simple Go functions that could potentially lead to such violations in the SSA (even if the compiler prevents this at a higher level) can be useful for creating illustrative examples.

11. **Command-Line Arguments:** Since this code is part of the internal compiler, it's unlikely to have direct user-facing command-line arguments. The analysis should reflect this.

12. **Common Mistakes:**  Consider situations where a compiler developer working on SSA might make errors. For example, forgetting to update successor/predecessor lists correctly, using the wrong number of arguments for an operation, or mismanaging memory flow are all potential pitfalls that these checks are designed to catch.

13. **Refine and Organize:**  Finally, organize the findings logically. Start with the high-level purpose, then detail the functionality of `checkFunc` and `memCheck`. Provide illustrative code examples and address the command-line argument and common mistake questions based on the analysis. Ensure the explanation is clear and concise.
这段代码是 Go 编译器中 SSA（Static Single Assignment）中间表示的一个检查模块，用于验证 SSA 函数 `f` 的内部一致性和正确性。 它的主要功能是**在编译过程中对生成的 SSA 代码进行一系列的健全性检查，确保 SSA 图的结构和属性符合预期，防止编译器内部错误导致生成的代码不正确。**

下面列举一下 `checkFunc` 函数的具体功能：

1. **基本结构检查:**
   - **块的唯一性:** 检查函数 `f` 中的每个基本块是否在 `f.Blocks` 中只出现一次。
   - **块的父函数:** 验证每个基本块 `b` 的 `b.Func` 属性是否指向当前的函数 `f`。
   - **块的连接:** 检查每个基本块的 `Preds` (前驱) 和 `Succs` (后继) 列表是否相互正确链接。如果 `b1` 是 `b2` 的前驱，那么 `b2` 必须是 `b1` 的后继，反之亦然。

2. **特定类型块的检查:**  根据基本块 `b` 的类型 (`b.Kind`) 执行特定的检查：
   - **`BlockExit`:** 确保退出块没有后继，并且只有一个内存类型的控制值。
   - **`BlockRet`:** 确保返回块没有后继，并且只有一个内存类型的控制值。
   - **`BlockRetJmp`:** 确保尾调用返回块没有后继，并且只有一个内存类型的控制值。
   - **`BlockPlain`:** 确保普通块只有一个后继，并且没有控制值。
   - **`BlockIf`:** 确保条件分支块有两个后继 (true 和 false 分支)，并且只有一个布尔类型的控制值。
   - **`BlockDefer`:** 确保 defer 块有两个后继，并且只有一个内存类型的控制值。
   - **`BlockFirst`:** 确保 `BlockFirst` 类型的块（通常是入口块或死代码块）有两个后继，并且没有控制值。
   - **`BlockJumpTable`:** 确保跳转表块只有一个控制值。
   - **分支预测:** 检查块的分支预测信息 (`b.Likely`) 是否与后继数量一致。

3. **值的检查:** 遍历每个基本块 `b` 中的每个 SSA 值 `v`，执行以下检查：
   - **参数数量:** 检查值的参数数量是否与操作码定义的参数数量一致。
   - **辅助值 (`Aux`) 的类型和值:**  根据操作码定义的 `auxType` 检查 `v.Aux` 和 `v.AuxInt` 的类型和取值范围是否合法。例如，对于布尔类型的 AuxInt，确保其值为 0 或 1。对于字符串类型的 Aux，确保 `v.Aux` 是 `stringAux` 类型。
   - **空参数:** 确保值的参数列表中没有 `nil`。
   - **内存参数位置:** 对于非 Phi 指令，内存类型的参数必须是最后一个参数。
   - **值的唯一性:** 检查每个 SSA 值是否只出现一次。
   - **值所属的块:** 验证 `v.Block` 属性是否指向包含它的基本块 `b`。
   - **Phi 指令参数数量:** 对于 `OpPhi` 指令，确保其参数数量与所在基本块的前驱数量一致。
   - **特定操作码的参数检查:**
     - **`OpAddr`:** 确保 `OpAddr` 指令至少有一个参数，且第一个参数是全局基址寄存器 `OpSB`。
     - **`OpLocalAddr`:** 确保 `OpLocalAddr` 指令有两个参数，第一个是栈指针寄存器 `OpSP`，第二个是内存类型。
   - **浮点数类型检查:** 在 `f.Config.SoftFloat` 为 true 的情况下（表示使用软件模拟浮点运算），不允许出现浮点数类型的值。
   - **类型检查:**  针对特定的操作码进行更细致的类型检查，例如 `OpSP` 和 `OpSB` 必须是 `uintptr` 类型，`OpStringLen` 必须是 `int` 类型，`OpLoad` 和 `OpStore` 的内存参数类型等。
   - **`OpVarDef` 检查:**  确保 `OpVarDef` 操作定义的名字要么拥有指针类型，要么是合并候选者。
   - **`OpNilCheck` 检查:**  在调度前后检查 `OpNilCheck` 的类型和参数类型是否符合预期。
   - **循环引用:**  虽然代码中有注释 `// TODO: check for cycles in values`，但当前版本似乎没有实现值的循环引用检查。

4. **块的可达性检查:**
   - 确保函数入口块 `f.Entry` 存在于 `f.Blocks` 中。
   - 检查所有被引用的前驱和后继基本块是否存在于 `f.Blocks` 中。

5. **入口块检查:** 确保函数的入口块 `f.Entry` 没有前驱。

6. **值引用的检查:**
   - 遍历所有基本块和值，确保所有被引用的参数都存在于函数中。
   - 检查所有控制值是否也存在于函数中。

7. **空闲列表检查:** 检查空闲块列表 (`f.freeBlocks`) 和空闲值列表 (`f.freeValues`) 中没有被使用过的块或值。

8. **支配关系检查:**
   - 如果未进行寄存器分配 (`f.RegAlloc == nil`)，则检查每个值的参数是否支配 (dominate) 该值所在的块。对于 `OpPhi` 指令，参数需要支配其对应的前驱块。
   - 检查每个块的控制值是否支配该块。

9. **循环结构检查:**
   - 如果未进行寄存器分配且存在 pass 信息 (`f.RegAlloc == nil && f.pass != nil`)，则检查 SSA 图的循环结构是否合法，例如不存在从非循环块到循环内部非头结点的跳转，以及从一个循环跳转到不包含它的另一个循环的内部非头结点的跳转。

10. **使用计数检查:**
    - 计算每个值实际被使用的次数。
    - 将计算出的使用次数与值的 `Uses` 字段进行比较，确保一致。

11. **内存一致性检查 (`memCheck` 函数):**
    - **元组内存类型位置:** 检查元组类型的 SSA 值，如果包含内存类型，则内存类型必须是第二个字段。
    - **单活跃内存检查:** (在没有内存拷贝的情况下) 尝试确保每个基本块中只有一个活跃的内存值。
    - **内存 Phi 指令一致性:**  检查内存类型的 `OpPhi` 指令，确保其参数与前驱块结束时的活跃内存值一致。
    - **调度后 Phi 指令位置:** 在调度后，检查 Phi 指令是否总是位于基本块的开头。

**可以推理出它是什么 Go 语言功能的实现：**

`check.go` 文件是 Go 编译器中用于实现**静态单赋值形式 (SSA)** 的一部分。 SSA 是一种中间表示形式，在编译器优化中被广泛使用。它具有以下关键特性：

- **每个变量只被赋值一次。** 如果一个变量需要被赋予新的值，将会创建一个新的 SSA 变量。
- **程序中的每个值都有一个唯一的定义点。**

这段代码的功能是确保编译器在生成 SSA 的过程中没有引入错误，保持 SSA 图的结构和语义的正确性。这对于后续的编译器优化至关重要，因为许多优化算法都依赖于 SSA 的这些特性。

**Go 代码举例说明：**

假设我们有以下简单的 Go 代码：

```go
package main

func add(a, b int) int {
	if a > 0 {
		return a + b
	}
	return b
}

func main() {
	result := add(5, 10)
	println(result)
}
```

当这段代码被 Go 编译器编译成 SSA 形式时，`checkFunc` 会对其生成的 SSA 图进行检查。例如，对于 `add` 函数的 `if` 语句，编译器会生成一个 `BlockIf` 类型的基本块，用于表示条件分支。`checkFunc` 会检查这个块是否恰好有两个后继块（true 分支和 false 分支），并且它的控制值（比较 `a > 0` 的结果）是一个布尔类型的值。

同样，对于 `a + b` 的操作，编译器会生成一个 `OpAdd` 类型的 SSA 值。`checkFunc` 会检查这个 `OpAdd` 值是否有两个参数，并且这两个参数的类型是整数类型。

**假设的输入与输出 (针对代码推理):**

假设 `checkFunc` 接收一个表示上面 `add` 函数的 SSA `*Func` 作为输入。

**输入 (简化表示):**

```
Func {
    Name: "add",
    Blocks: []*Block{
        {
            ID: 1,
            Kind: BlockFirst,
            Succs: [{ID: 2}, {ID: 3}],
            // ... other fields
        },
        {
            ID: 2,
            Kind: BlockIf,
            Controls: [Value{Op: OpGt, Args: [Value{Op: OpArg, AuxInt: 0}, Value{Op: OpConst, AuxInt: 0}]}],
            Succs: [{ID: 4}, {ID: 5}],
            // ... other fields
        },
        {
            ID: 3,
            Kind: BlockPlain,
            Succs: [{ID: 5}],
            // ... other fields
        },
        {
            ID: 4,
            Kind: BlockPlain,
            Values: [Value{Op: OpAdd, Args: [Value{Op: OpArg, AuxInt: 0}, Value{Op: OpArg, AuxInt: 1}]}],
            Succs: [{ID: 6}],
            // ... other fields
        },
        {
            ID: 5,
            Kind: BlockPlain,
            Values: [Value{Op: OpArg, AuxInt: 1}],
            Succs: [{ID: 6}],
            // ... other fields
        },
        {
            ID: 6,
            Kind: BlockRet,
            Controls: [Value{Op: OpPhi, Args: [Value{Op: OpAdd, ...}, Value{Op: OpArg, ...}]}],
            // ... other fields
        },
    },
    // ... other fields
}
```

**输出 (如果没有错误):**

`checkFunc` 函数不会显式返回一个值。它的作用是在检查过程中如果发现任何不一致性，会调用 `f.Fatalf` 抛出致命错误，导致编译过程停止。 如果所有检查都通过，则函数正常结束，没有输出。

**命令行参数的具体处理:**

`check.go` 文件本身不直接处理命令行参数。它是 Go 编译器内部的一部分，由编译器主程序调用。Go 编译器的命令行参数，例如 `-gcflags`，可以影响编译过程，间接影响 SSA 的生成和检查，但 `check.go` 不负责解析这些参数。

**使用者易犯错的点:**

由于 `check.go` 是 Go 编译器内部的检查模块，**直接的使用者是 Go 编译器的开发者，而不是普通的 Go 语言使用者。**  编译器开发者在修改或扩展编译器的 SSA 生成或优化部分时，可能会犯以下错误，而 `checkFunc` 可以帮助检测这些错误：

1. **不正确的块连接:**  例如，在创建新的控制流分支时，忘记正确设置前驱和后继关系。`checkFunc` 会通过 `block pred/succ not crosslinked correctly` 的错误信息来提示。
2. **错误的操作码参数:** 为某个操作码提供了错误数量或类型的参数。`checkFunc` 会通过 `value %s has %d args, expected %d` 或 `bad arg type to %s` 等错误信息来提示。
3. **辅助值 (`Aux`) 使用不当:**  为操作码设置了错误类型或值的 `Aux` 字段。`checkFunc` 中大量的 `switch opcodeTable[v.Op].auxType` 检查就是为了防止这类错误。
4. **内存操作不当:**  例如，在没有正确维护内存依赖关系的情况下生成内存操作指令。`memCheck` 函数中的检查，如 `two live memory values in %s`，可以帮助发现这类问题。
5. **违反 SSA 规则:**  例如，错误地为一个 SSA 变量多次赋值 (尽管 Go 的 SSA 生成器应该避免这种情况，但检查仍然是一种保障)。
6. **支配关系错误:**  在进行某些优化时，可能会错误地移动代码，导致支配关系被破坏。`checkFunc` 中的支配关系检查可以捕获这些错误。

总之，`go/src/cmd/compile/internal/ssa/check.go` 是 Go 编译器中一个关键的组成部分，它通过执行一系列细致的检查，确保生成的 SSA 代码的正确性和一致性，为后续的编译器优化和最终代码生成奠定坚实的基础。 这对于保证 Go 语言编译器的可靠性和生成代码的正确性至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/ssa/check.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"cmd/compile/internal/ir"
	"cmd/internal/obj/s390x"
	"math"
	"math/bits"
)

// checkFunc checks invariants of f.
func checkFunc(f *Func) {
	blockMark := make([]bool, f.NumBlocks())
	valueMark := make([]bool, f.NumValues())

	for _, b := range f.Blocks {
		if blockMark[b.ID] {
			f.Fatalf("block %s appears twice in %s!", b, f.Name)
		}
		blockMark[b.ID] = true
		if b.Func != f {
			f.Fatalf("%s.Func=%s, want %s", b, b.Func.Name, f.Name)
		}

		for i, e := range b.Preds {
			if se := e.b.Succs[e.i]; se.b != b || se.i != i {
				f.Fatalf("block pred/succ not crosslinked correctly %d:%s %d:%s", i, b, se.i, se.b)
			}
		}
		for i, e := range b.Succs {
			if pe := e.b.Preds[e.i]; pe.b != b || pe.i != i {
				f.Fatalf("block succ/pred not crosslinked correctly %d:%s %d:%s", i, b, pe.i, pe.b)
			}
		}

		switch b.Kind {
		case BlockExit:
			if len(b.Succs) != 0 {
				f.Fatalf("exit block %s has successors", b)
			}
			if b.NumControls() != 1 {
				f.Fatalf("exit block %s has no control value", b)
			}
			if !b.Controls[0].Type.IsMemory() {
				f.Fatalf("exit block %s has non-memory control value %s", b, b.Controls[0].LongString())
			}
		case BlockRet:
			if len(b.Succs) != 0 {
				f.Fatalf("ret block %s has successors", b)
			}
			if b.NumControls() != 1 {
				f.Fatalf("ret block %s has nil control", b)
			}
			if !b.Controls[0].Type.IsMemory() {
				f.Fatalf("ret block %s has non-memory control value %s", b, b.Controls[0].LongString())
			}
		case BlockRetJmp:
			if len(b.Succs) != 0 {
				f.Fatalf("retjmp block %s len(Succs)==%d, want 0", b, len(b.Succs))
			}
			if b.NumControls() != 1 {
				f.Fatalf("retjmp block %s has nil control", b)
			}
			if !b.Controls[0].Type.IsMemory() {
				f.Fatalf("retjmp block %s has non-memory control value %s", b, b.Controls[0].LongString())
			}
		case BlockPlain:
			if len(b.Succs) != 1 {
				f.Fatalf("plain block %s len(Succs)==%d, want 1", b, len(b.Succs))
			}
			if b.NumControls() != 0 {
				f.Fatalf("plain block %s has non-nil control %s", b, b.Controls[0].LongString())
			}
		case BlockIf:
			if len(b.Succs) != 2 {
				f.Fatalf("if block %s len(Succs)==%d, want 2", b, len(b.Succs))
			}
			if b.NumControls() != 1 {
				f.Fatalf("if block %s has no control value", b)
			}
			if !b.Controls[0].Type.IsBoolean() {
				f.Fatalf("if block %s has non-bool control value %s", b, b.Controls[0].LongString())
			}
		case BlockDefer:
			if len(b.Succs) != 2 {
				f.Fatalf("defer block %s len(Succs)==%d, want 2", b, len(b.Succs))
			}
			if b.NumControls() != 1 {
				f.Fatalf("defer block %s has no control value", b)
			}
			if !b.Controls[0].Type.IsMemory() {
				f.Fatalf("defer block %s has non-memory control value %s", b, b.Controls[0].LongString())
			}
		case BlockFirst:
			if len(b.Succs) != 2 {
				f.Fatalf("plain/dead block %s len(Succs)==%d, want 2", b, len(b.Succs))
			}
			if b.NumControls() != 0 {
				f.Fatalf("plain/dead block %s has a control value", b)
			}
		case BlockJumpTable:
			if b.NumControls() != 1 {
				f.Fatalf("jumpTable block %s has no control value", b)
			}
		}
		if len(b.Succs) != 2 && b.Likely != BranchUnknown {
			f.Fatalf("likeliness prediction %d for block %s with %d successors", b.Likely, b, len(b.Succs))
		}

		for _, v := range b.Values {
			// Check to make sure argument count makes sense (argLen of -1 indicates
			// variable length args)
			nArgs := opcodeTable[v.Op].argLen
			if nArgs != -1 && int32(len(v.Args)) != nArgs {
				f.Fatalf("value %s has %d args, expected %d", v.LongString(),
					len(v.Args), nArgs)
			}

			// Check to make sure aux values make sense.
			canHaveAux := false
			canHaveAuxInt := false
			// TODO: enforce types of Aux in this switch (like auxString does below)
			switch opcodeTable[v.Op].auxType {
			case auxNone:
			case auxBool:
				if v.AuxInt < 0 || v.AuxInt > 1 {
					f.Fatalf("bad bool AuxInt value for %v", v)
				}
				canHaveAuxInt = true
			case auxInt8:
				if v.AuxInt != int64(int8(v.AuxInt)) {
					f.Fatalf("bad int8 AuxInt value for %v", v)
				}
				canHaveAuxInt = true
			case auxInt16:
				if v.AuxInt != int64(int16(v.AuxInt)) {
					f.Fatalf("bad int16 AuxInt value for %v", v)
				}
				canHaveAuxInt = true
			case auxInt32:
				if v.AuxInt != int64(int32(v.AuxInt)) {
					f.Fatalf("bad int32 AuxInt value for %v", v)
				}
				canHaveAuxInt = true
			case auxInt64, auxARM64BitField:
				canHaveAuxInt = true
			case auxInt128:
				// AuxInt must be zero, so leave canHaveAuxInt set to false.
			case auxUInt8:
				if v.AuxInt != int64(uint8(v.AuxInt)) {
					f.Fatalf("bad uint8 AuxInt value for %v", v)
				}
				canHaveAuxInt = true
			case auxFloat32:
				canHaveAuxInt = true
				if math.IsNaN(v.AuxFloat()) {
					f.Fatalf("value %v has an AuxInt that encodes a NaN", v)
				}
				if !isExactFloat32(v.AuxFloat()) {
					f.Fatalf("value %v has an AuxInt value that is not an exact float32", v)
				}
			case auxFloat64:
				canHaveAuxInt = true
				if math.IsNaN(v.AuxFloat()) {
					f.Fatalf("value %v has an AuxInt that encodes a NaN", v)
				}
			case auxString:
				if _, ok := v.Aux.(stringAux); !ok {
					f.Fatalf("value %v has Aux type %T, want string", v, v.Aux)
				}
				canHaveAux = true
			case auxCallOff:
				canHaveAuxInt = true
				fallthrough
			case auxCall:
				if ac, ok := v.Aux.(*AuxCall); ok {
					if v.Op == OpStaticCall && ac.Fn == nil {
						f.Fatalf("value %v has *AuxCall with nil Fn", v)
					}
				} else {
					f.Fatalf("value %v has Aux type %T, want *AuxCall", v, v.Aux)
				}
				canHaveAux = true
			case auxNameOffsetInt8:
				if _, ok := v.Aux.(*AuxNameOffset); !ok {
					f.Fatalf("value %v has Aux type %T, want *AuxNameOffset", v, v.Aux)
				}
				canHaveAux = true
				canHaveAuxInt = true
			case auxSym, auxTyp:
				canHaveAux = true
			case auxSymOff, auxSymValAndOff, auxTypSize:
				canHaveAuxInt = true
				canHaveAux = true
			case auxCCop:
				if opcodeTable[Op(v.AuxInt)].name == "OpInvalid" {
					f.Fatalf("value %v has an AuxInt value that is a valid opcode", v)
				}
				canHaveAuxInt = true
			case auxS390XCCMask:
				if _, ok := v.Aux.(s390x.CCMask); !ok {
					f.Fatalf("bad type %T for S390XCCMask in %v", v.Aux, v)
				}
				canHaveAux = true
			case auxS390XRotateParams:
				if _, ok := v.Aux.(s390x.RotateParams); !ok {
					f.Fatalf("bad type %T for S390XRotateParams in %v", v.Aux, v)
				}
				canHaveAux = true
			case auxFlagConstant:
				if v.AuxInt < 0 || v.AuxInt > 15 {
					f.Fatalf("bad FlagConstant AuxInt value for %v", v)
				}
				canHaveAuxInt = true
			default:
				f.Fatalf("unknown aux type for %s", v.Op)
			}
			if !canHaveAux && v.Aux != nil {
				f.Fatalf("value %s has an Aux value %v but shouldn't", v.LongString(), v.Aux)
			}
			if !canHaveAuxInt && v.AuxInt != 0 {
				f.Fatalf("value %s has an AuxInt value %d but shouldn't", v.LongString(), v.AuxInt)
			}

			for i, arg := range v.Args {
				if arg == nil {
					f.Fatalf("value %s has nil arg", v.LongString())
				}
				if v.Op != OpPhi {
					// For non-Phi ops, memory args must be last, if present
					if arg.Type.IsMemory() && i != len(v.Args)-1 {
						f.Fatalf("value %s has non-final memory arg (%d < %d)", v.LongString(), i, len(v.Args)-1)
					}
				}
			}

			if valueMark[v.ID] {
				f.Fatalf("value %s appears twice!", v.LongString())
			}
			valueMark[v.ID] = true

			if v.Block != b {
				f.Fatalf("%s.block != %s", v, b)
			}
			if v.Op == OpPhi && len(v.Args) != len(b.Preds) {
				f.Fatalf("phi length %s does not match pred length %d for block %s", v.LongString(), len(b.Preds), b)
			}

			if v.Op == OpAddr {
				if len(v.Args) == 0 {
					f.Fatalf("no args for OpAddr %s", v.LongString())
				}
				if v.Args[0].Op != OpSB {
					f.Fatalf("bad arg to OpAddr %v", v)
				}
			}

			if v.Op == OpLocalAddr {
				if len(v.Args) != 2 {
					f.Fatalf("wrong # of args for OpLocalAddr %s", v.LongString())
				}
				if v.Args[0].Op != OpSP {
					f.Fatalf("bad arg 0 to OpLocalAddr %v", v)
				}
				if !v.Args[1].Type.IsMemory() {
					f.Fatalf("bad arg 1 to OpLocalAddr %v", v)
				}
			}

			if f.RegAlloc != nil && f.Config.SoftFloat && v.Type.IsFloat() {
				f.Fatalf("unexpected floating-point type %v", v.LongString())
			}

			// Check types.
			// TODO: more type checks?
			switch c := f.Config; v.Op {
			case OpSP, OpSB:
				if v.Type != c.Types.Uintptr {
					f.Fatalf("bad %s type: want uintptr, have %s",
						v.Op, v.Type.String())
				}
			case OpStringLen:
				if v.Type != c.Types.Int {
					f.Fatalf("bad %s type: want int, have %s",
						v.Op, v.Type.String())
				}
			case OpLoad:
				if !v.Args[1].Type.IsMemory() {
					f.Fatalf("bad arg 1 type to %s: want mem, have %s",
						v.Op, v.Args[1].Type.String())
				}
			case OpStore:
				if !v.Type.IsMemory() {
					f.Fatalf("bad %s type: want mem, have %s",
						v.Op, v.Type.String())
				}
				if !v.Args[2].Type.IsMemory() {
					f.Fatalf("bad arg 2 type to %s: want mem, have %s",
						v.Op, v.Args[2].Type.String())
				}
			case OpCondSelect:
				if !v.Args[2].Type.IsBoolean() {
					f.Fatalf("bad arg 2 type to %s: want boolean, have %s",
						v.Op, v.Args[2].Type.String())
				}
			case OpAddPtr:
				if !v.Args[0].Type.IsPtrShaped() && v.Args[0].Type != c.Types.Uintptr {
					f.Fatalf("bad arg 0 type to %s: want ptr, have %s", v.Op, v.Args[0].LongString())
				}
				if !v.Args[1].Type.IsInteger() {
					f.Fatalf("bad arg 1 type to %s: want integer, have %s", v.Op, v.Args[1].LongString())
				}
			case OpVarDef:
				n := v.Aux.(*ir.Name)
				if !n.Type().HasPointers() && !IsMergeCandidate(n) {
					f.Fatalf("vardef must be merge candidate or have pointer type %s", v.Aux.(*ir.Name).Type().String())
				}
			case OpNilCheck:
				// nil checks have pointer type before scheduling, and
				// void type after scheduling.
				if f.scheduled {
					if v.Uses != 0 {
						f.Fatalf("nilcheck must have 0 uses %s", v.Uses)
					}
					if !v.Type.IsVoid() {
						f.Fatalf("nilcheck must have void type %s", v.Type.String())
					}
				} else {
					if !v.Type.IsPtrShaped() && !v.Type.IsUintptr() {
						f.Fatalf("nilcheck must have pointer type %s", v.Type.String())
					}
				}
				if !v.Args[0].Type.IsPtrShaped() && !v.Args[0].Type.IsUintptr() {
					f.Fatalf("nilcheck must have argument of pointer type %s", v.Args[0].Type.String())
				}
				if !v.Args[1].Type.IsMemory() {
					f.Fatalf("bad arg 1 type to %s: want mem, have %s",
						v.Op, v.Args[1].Type.String())
				}
			}

			// TODO: check for cycles in values
		}
	}

	// Check to make sure all Blocks referenced are in the function.
	if !blockMark[f.Entry.ID] {
		f.Fatalf("entry block %v is missing", f.Entry)
	}
	for _, b := range f.Blocks {
		for _, c := range b.Preds {
			if !blockMark[c.b.ID] {
				f.Fatalf("predecessor block %v for %v is missing", c, b)
			}
		}
		for _, c := range b.Succs {
			if !blockMark[c.b.ID] {
				f.Fatalf("successor block %v for %v is missing", c, b)
			}
		}
	}

	if len(f.Entry.Preds) > 0 {
		f.Fatalf("entry block %s of %s has predecessor(s) %v", f.Entry, f.Name, f.Entry.Preds)
	}

	// Check to make sure all Values referenced are in the function.
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for i, a := range v.Args {
				if !valueMark[a.ID] {
					f.Fatalf("%v, arg %d of %s, is missing", a, i, v.LongString())
				}
			}
		}
		for _, c := range b.ControlValues() {
			if !valueMark[c.ID] {
				f.Fatalf("control value for %s is missing: %v", b, c)
			}
		}
	}
	for b := f.freeBlocks; b != nil; b = b.succstorage[0].b {
		if blockMark[b.ID] {
			f.Fatalf("used block b%d in free list", b.ID)
		}
	}
	for v := f.freeValues; v != nil; v = v.argstorage[0] {
		if valueMark[v.ID] {
			f.Fatalf("used value v%d in free list", v.ID)
		}
	}

	// Check to make sure all args dominate uses.
	if f.RegAlloc == nil {
		// Note: regalloc introduces non-dominating args.
		// See TODO in regalloc.go.
		sdom := f.Sdom()
		for _, b := range f.Blocks {
			for _, v := range b.Values {
				for i, arg := range v.Args {
					x := arg.Block
					y := b
					if v.Op == OpPhi {
						y = b.Preds[i].b
					}
					if !domCheck(f, sdom, x, y) {
						f.Fatalf("arg %d of value %s does not dominate, arg=%s", i, v.LongString(), arg.LongString())
					}
				}
			}
			for _, c := range b.ControlValues() {
				if !domCheck(f, sdom, c.Block, b) {
					f.Fatalf("control value %s for %s doesn't dominate", c, b)
				}
			}
		}
	}

	// Check loop construction
	if f.RegAlloc == nil && f.pass != nil { // non-nil pass allows better-targeted debug printing
		ln := f.loopnest()
		if !ln.hasIrreducible {
			po := f.postorder() // use po to avoid unreachable blocks.
			for _, b := range po {
				for _, s := range b.Succs {
					bb := s.Block()
					if ln.b2l[b.ID] == nil && ln.b2l[bb.ID] != nil && bb != ln.b2l[bb.ID].header {
						f.Fatalf("block %s not in loop branches to non-header block %s in loop", b.String(), bb.String())
					}
					if ln.b2l[b.ID] != nil && ln.b2l[bb.ID] != nil && bb != ln.b2l[bb.ID].header && !ln.b2l[b.ID].isWithinOrEq(ln.b2l[bb.ID]) {
						f.Fatalf("block %s in loop branches to non-header block %s in non-containing loop", b.String(), bb.String())
					}
				}
			}
		}
	}

	// Check use counts
	uses := make([]int32, f.NumValues())
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			for _, a := range v.Args {
				uses[a.ID]++
			}
		}
		for _, c := range b.ControlValues() {
			uses[c.ID]++
		}
	}
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Uses != uses[v.ID] {
				f.Fatalf("%s has %d uses, but has Uses=%d", v, uses[v.ID], v.Uses)
			}
		}
	}

	memCheck(f)
}

func memCheck(f *Func) {
	// Check that if a tuple has a memory type, it is second.
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Type.IsTuple() && v.Type.FieldType(0).IsMemory() {
				f.Fatalf("memory is first in a tuple: %s\n", v.LongString())
			}
		}
	}

	// Single live memory checks.
	// These checks only work if there are no memory copies.
	// (Memory copies introduce ambiguity about which mem value is really live.
	// probably fixable, but it's easier to avoid the problem.)
	// For the same reason, disable this check if some memory ops are unused.
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if (v.Op == OpCopy || v.Uses == 0) && v.Type.IsMemory() {
				return
			}
		}
		if b != f.Entry && len(b.Preds) == 0 {
			return
		}
	}

	// Compute live memory at the end of each block.
	lastmem := make([]*Value, f.NumBlocks())
	ss := newSparseSet(f.NumValues())
	for _, b := range f.Blocks {
		// Mark overwritten memory values. Those are args of other
		// ops that generate memory values.
		ss.clear()
		for _, v := range b.Values {
			if v.Op == OpPhi || !v.Type.IsMemory() {
				continue
			}
			if m := v.MemoryArg(); m != nil {
				ss.add(m.ID)
			}
		}
		// There should be at most one remaining unoverwritten memory value.
		for _, v := range b.Values {
			if !v.Type.IsMemory() {
				continue
			}
			if ss.contains(v.ID) {
				continue
			}
			if lastmem[b.ID] != nil {
				f.Fatalf("two live memory values in %s: %s and %s", b, lastmem[b.ID], v)
			}
			lastmem[b.ID] = v
		}
		// If there is no remaining memory value, that means there was no memory update.
		// Take any memory arg.
		if lastmem[b.ID] == nil {
			for _, v := range b.Values {
				if v.Op == OpPhi {
					continue
				}
				m := v.MemoryArg()
				if m == nil {
					continue
				}
				if lastmem[b.ID] != nil && lastmem[b.ID] != m {
					f.Fatalf("two live memory values in %s: %s and %s", b, lastmem[b.ID], m)
				}
				lastmem[b.ID] = m
			}
		}
	}
	// Propagate last live memory through storeless blocks.
	for {
		changed := false
		for _, b := range f.Blocks {
			if lastmem[b.ID] != nil {
				continue
			}
			for _, e := range b.Preds {
				p := e.b
				if lastmem[p.ID] != nil {
					lastmem[b.ID] = lastmem[p.ID]
					changed = true
					break
				}
			}
		}
		if !changed {
			break
		}
	}
	// Check merge points.
	for _, b := range f.Blocks {
		for _, v := range b.Values {
			if v.Op == OpPhi && v.Type.IsMemory() {
				for i, a := range v.Args {
					if a != lastmem[b.Preds[i].b.ID] {
						f.Fatalf("inconsistent memory phi %s %d %s %s", v.LongString(), i, a, lastmem[b.Preds[i].b.ID])
					}
				}
			}
		}
	}

	// Check that only one memory is live at any point.
	if f.scheduled {
		for _, b := range f.Blocks {
			var mem *Value // the current live memory in the block
			for _, v := range b.Values {
				if v.Op == OpPhi {
					if v.Type.IsMemory() {
						mem = v
					}
					continue
				}
				if mem == nil && len(b.Preds) > 0 {
					// If no mem phi, take mem of any predecessor.
					mem = lastmem[b.Preds[0].b.ID]
				}
				for _, a := range v.Args {
					if a.Type.IsMemory() && a != mem {
						f.Fatalf("two live mems @ %s: %s and %s", v, mem, a)
					}
				}
				if v.Type.IsMemory() {
					mem = v
				}
			}
		}
	}

	// Check that after scheduling, phis are always first in the block.
	if f.scheduled {
		for _, b := range f.Blocks {
			seenNonPhi := false
			for _, v := range b.Values {
				switch v.Op {
				case OpPhi:
					if seenNonPhi {
						f.Fatalf("phi after non-phi @ %s: %s", b, v)
					}
				default:
					seenNonPhi = true
				}
			}
		}
	}
}

// domCheck reports whether x dominates y (including x==y).
func domCheck(f *Func, sdom SparseTree, x, y *Block) bool {
	if !sdom.IsAncestorEq(f.Entry, y) {
		// unreachable - ignore
		return true
	}
	return sdom.IsAncestorEq(x, y)
}

// isExactFloat32 reports whether x can be exactly represented as a float32.
func isExactFloat32(x float64) bool {
	// Check the mantissa is in range.
	if bits.TrailingZeros64(math.Float64bits(x)) < 52-23 {
		return false
	}
	// Check the exponent is in range. The mantissa check above is sufficient for NaN values.
	return math.IsNaN(x) || x == float64(float32(x))
}
```