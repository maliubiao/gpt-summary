Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a breakdown of the functionality of the provided Go code snippet (`sanity.go`). It emphasizes understanding the code's purpose, illustrating its usage with Go examples, explaining command-line arguments (if any), and highlighting potential user errors.

2. **Initial Skim and Keyword Identification:** I quickly scan the code for important keywords and structural elements. I notice:
    * `package ssa` -  Indicates this code is part of an SSA (Static Single Assignment) representation package.
    * `sanity` struct - Suggests the core logic revolves around this structure.
    * `sanityCheck`, `mustSanityCheck` - These function names clearly indicate the primary purpose: checking the sanity/validity of SSA.
    * `reporter io.Writer` - Hints at how diagnostic information is outputted.
    * `diagnostic`, `errorf`, `warnf` - Methods for reporting issues.
    * The various `check...` methods (`checkFunction`, `checkBlock`, `checkInstr`, etc.) - Point to the different levels of SSA representation being checked.
    * The `switch instr := instr.(type)` blocks - Show the specific checks performed on different SSA instruction types.

3. **Identify Core Functionality:** Based on the keywords and function names, the central function is definitely about validating the internal consistency of an SSA representation of a Go program. This involves checking various aspects of the SSA structure.

4. **Break Down Functionality into Specific Checks:** I go through the `check...` methods in more detail to understand what specific invariants are being validated. I group these checks conceptually:
    * **Function Level:**  Checks on the `Function` object itself (e.g., `Prog`, `Pkg`, `Locals`, `Params`, `FreeVars`).
    * **Basic Block Level:** Checks on the structure of `BasicBlock`s (e.g., `Index`, `parent`, predecessor/successor relationships, reachability).
    * **Instruction Level:** Checks on individual `Instruction`s within a basic block. This includes:
        * **Control Flow:** Ensuring control flow instructions are at the end of blocks.
        * **Phi Nodes:** Validating the number of edges and their connection to predecessors.
        * **Instruction-Specific Checks:** Many `case` statements handle specific instruction types (`Alloc`, `BinOp`, `Call`, etc.), verifying their internal consistency and relationships with other SSA elements.
        * **Operand Checks:** Ensuring operands are valid, typed correctly, and refer back to the instruction when appropriate.
        * **Referrer Lists:**  Verifying that values correctly track which instructions use them.

5. **Infer Go Language Feature:** The code directly manipulates and validates an SSA representation. SSA is a compiler intermediate representation, so this code is primarily a tool for compiler development or analysis. It doesn't directly implement a standard Go language feature visible to the average Go programmer. However, it *supports* the correct functioning of Go features by ensuring the internal representation used by the compiler is valid.

6. **Illustrative Go Code Example:** Since the code itself isn't a feature a regular programmer uses directly, demonstrating its use requires showing how one might obtain an SSA representation of Go code and then use the `sanityCheck` function. This involves using the `go/packages` and `golang.org/x/tools/go/ssa` packages. The example should show the basic steps of loading and building SSA.

7. **Command-Line Arguments:** I carefully review the code for any command-line argument parsing. I notice there are *no* direct command-line argument handling within this code snippet. The `reporter` is passed programmatically.

8. **Potential User Errors:** This is tricky because regular users don't directly interact with this code. The "users" in this context are likely *compiler developers* or those writing tools that manipulate SSA. The most common error would be introducing a transformation that violates one of the invariants being checked by the `sanityCheck` function. I focus on examples like incorrect manipulation of block predecessors/successors or introducing malformed instructions.

9. **Structure the Answer:** I organize the answer logically, addressing each part of the request:
    * **功能列举:**  Provide a bulleted list of the key functionalities.
    * **Go 语言功能实现推理:** Explain that it's not a direct language feature but a tool for SSA validation. Provide the illustrative Go code example.
    * **代码推理 (带假设输入与输出):** While the code *performs* checks, it doesn't inherently have a single "input and output" in the traditional sense. The "input" is the SSA representation, and the "output" is a boolean indicating validity and diagnostic messages. I clarify this.
    * **命令行参数:** Explicitly state that there are no command-line arguments.
    * **使用者易犯错的点:** Provide examples of errors compiler developers might make.

10. **Refine and Translate:** I review the entire answer for clarity, accuracy, and completeness, ensuring it's written in clear Chinese as requested. I pay attention to using precise terminology related to SSA and compiler concepts.

By following these steps, I can systematically analyze the code and generate a comprehensive and accurate answer that addresses all aspects of the user's request.
这段代码是 Go 语言 `ssa` 包（`golang.org/x/tools/go/ssa`）中用于进行 SSA（Static Single Assignment，静态单赋值）表示的完整性检查的一部分。它的主要功能是 **验证 SSA 形式的代码是否满足一系列预定义的规则和约束，以确保其内部一致性和正确性**。

下面列举它的主要功能：

1. **函数级别的检查 (`checkFunction`)**:
   - 检查 `Function` 对象的各种属性是否正确，例如 `Prog` (程序对象), `Pkg` (包对象), `Locals` (局部变量), `Params` (参数), `FreeVars` (自由变量) 等。
   - 验证局部变量是否正确地属于当前函数。
   - 检查参数和自由变量的引用者列表 (Referrers) 是否正确。
   - 检查函数中的基本块列表 (`Blocks`) 是否为空或包含 `nil`。
   - 验证 `Recover` 块（如果存在）是否在 `Blocks` 列表中。
   - 递归地检查匿名函数。

2. **基本块级别的检查 (`checkBlock`)**:
   - 检查 `BasicBlock` 对象的属性，例如 `Index` (索引) 和 `parent` (父函数)。
   - 检查基本块是否可达（除了入口块和 `Recover` 块）。
   - 验证前驱节点 (`Preds`) 和后继节点 (`Succs`) 关系是否互逆，并且所有块都属于同一个函数。
   - 遍历基本块中的每条指令，并调用 `checkInstr` 和 `checkFinalInstr` 进行更详细的检查。

3. **指令级别的检查 (`checkInstr` 和 `checkFinalInstr`)**:
   - `checkInstr` 检查**非**基本块末尾的指令：
     - 确保控制流指令 (`If`, `Jump`, `Return`, `Panic`) 不出现在块的中间。
     - 检查 `Phi` 指令的正确性，例如是否有重复的前驱节点，以及边的数量是否与前驱节点数量匹配。
     - 检查 `Alloc` 指令（本地分配）是否在 `Function.Locals` 中。
     - 对各种类型的指令 (`BinOp`, `Call`, `Convert`, `MakeClosure` 等) 进行特定的检查，例如类型转换的类型约束，闭包的绑定数量等。
     - 检查值定义指令 (`Value` 接口的实现) 是否有有效的类型和引用者列表。
   - `checkFinalInstr` 检查基本块末尾的控制流指令：
     - 检查 `If` 指令是否有两个不同的后继节点。
     - 检查 `Jump` 指令是否只有一个后继节点。
     - 检查 `Return` 指令是否有零个后继节点，并且返回值数量与函数签名匹配。
     - 检查 `Panic` 指令是否有零个后继节点。
     - 确保基本块的末尾是控制流指令。

4. **引用者列表的检查 (`checkReferrerList`)**:
   - 验证一个 `Value` 的引用者列表中的每个引用是否都是属于当前函数的指令。

5. **包级别的检查 (`sanityCheckPackage`)**:
   - 检查 `Package` 对象的基本属性，例如 `Pkg` (types.Package 对象)。
   - 验证包成员的名字是否与其 `Name()` 方法返回的值一致。
   - 验证包成员的 `Object()` 方法返回的 `types.Object` 的名字和位置是否一致。

**Go 语言功能实现推理和代码举例:**

这段代码本身 **不是** 某个特定的 Go 语言功能的实现，而是用于 **验证** 由 `ssa` 包生成的 SSA 代码的正确性。`ssa` 包的目标是为 Go 语言代码生成静态单赋值形式的中间表示，这通常用于编译器优化、静态分析等场景。

可以这样理解：`ssa` 包负责将 Go 源代码转换为 SSA 形式，而 `sanity.go` 中的代码则像一个“质量检查员”，确保转换后的 SSA 代码没有违反任何预期的规则。

**举例说明：`Phi` 指令的检查**

假设我们有以下简单的 Go 代码：

```go
package main

func f(x int) int {
	if x > 0 {
		x = 10
	} else {
		x = 20
	}
	return x
}
```

`ssa` 包可能会将其转换为类似以下的控制流图 (CFG)：

```
Entry -> B1 -> B2 -> Return
B1 (if x > 0):
  True -> B2
  False -> B3
B3:
  x = 20
  Jump -> B2
B2:
  x = Phi(B1: 10, B3: 20) // 如果从 B1 来，x 的值是 10，如果从 B3 来，x 的值是 20
Return:
  return x
```

`sanity.go` 中的 `checkInstr` 函数会检查 `Phi` 指令的正确性：

```go
case *Phi:
	if idx == 0 {
		// ...
	} else {
		// ...
	}
	if ne, np := len(instr.Edges), len(s.block.Preds); ne != np {
		s.errorf("phi node has %d edges but %d predecessors", ne, np)

	} else {
		for i, e := range instr.Edges {
			if e == nil {
				s.errorf("phi node '%s' has no value for edge #%d from %s", instr.Comment, i, s.block.Preds[i])
			}
		}
	}
```

**假设输入:** 一个包含上述 `Phi` 指令的 `ssa.BasicBlock` 对象。

**输出:** 如果 `Phi` 指令的边数 (`len(instr.Edges)`) 与其所在基本块的前驱节点数 (`len(s.block.Preds)`) 不一致，或者某个边没有对应的输入值 (`e == nil`)，则会调用 `s.errorf` 报告错误。

**命令行参数的具体处理:**

这段代码本身 **不处理** 任何命令行参数。它是一个内部使用的代码，通常被 `go/ssa` 包或其他使用 `go/ssa` 的工具调用。调用 `sanityCheck` 或 `mustSanityCheck` 时，会传入要检查的 `ssa.Function` 对象以及一个可选的 `io.Writer` 用于输出诊断信息。如果没有提供 `io.Writer`，则默认使用 `os.Stderr`。

**使用者易犯错的点:**

由于 `sanity.go` 是用于内部检查的，直接的使用者通常是开发 `go/ssa` 包或相关工具的开发者。他们容易犯错的点可能包括：

1. **在转换或生成 SSA 代码时，错误地维护了基本块的前驱和后继关系。** 例如，在添加或删除边时没有正确更新两端的连接。这会导致 `checkBlock` 中关于前驱后继关系不一致的错误。

   ```go
   // 错误示例：假设 blockA 是 blockB 的前驱，但 blockB 的 Preds 中没有 blockA
   // ... 在修改 SSA 代码的逻辑中 ...
   blockA.Succs = append(blockA.Succs, blockB)
   // 忘记更新 blockB.Preds = append(blockB.Preds, blockA)
   ```

2. **在创建 `Phi` 指令时，提供的边数与前驱节点的数量不匹配。**

   ```go
   // 错误示例：blockB 有两个前驱，但 Phi 指令只提供了 1 个输入值
   phi := &ssa.Phi{
       Edges: []ssa.Value{valueFromPred1}, // 缺少来自第二个前驱的输入值
   }
   blockB.Instrs = append(blockB.Instrs, phi)
   ```

3. **在指令的操作数中使用了类型不一致的值。** 例如，将一个非布尔类型的值作为 `If` 指令的条件。

   ```go
   // 错误示例：If 指令的条件不是布尔类型
   ifInstr := &ssa.If{
       Cond: nonBoolValue,
   }
   block.Instrs = append(block.Instrs, ifInstr)
   ```

4. **修改 SSA 代码后，没有正确更新值的引用者列表 (`Referrers`)。** 这会导致 `checkReferrerList` 中报告错误。

   ```go
   // 错误示例：假设 instruction 使用了 value，但 value 的 Referrers 中没有 instruction
   // ... 在修改 SSA 代码的逻辑中 ...
   // 添加了 instruction 使用 value 的代码，但忘记更新 value 的 Referrers
   ```

总而言之，`go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/sanity.go` 中的代码是 `ssa` 包中至关重要的一部分，用于确保生成的 SSA 代码的正确性和一致性，这对于依赖于 SSA 的后续分析和优化步骤至关重要。虽然普通 Go 开发者不会直接调用这些函数，但它们是构建可靠的 Go 工具链的基础。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/sanity.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssa

// An optional pass for sanity-checking invariants of the SSA representation.
// Currently it checks CFG invariants but little at the instruction level.

import (
	"fmt"
	"go/types"
	"io"
	"os"
	"strings"
)

type sanity struct {
	reporter io.Writer
	fn       *Function
	block    *BasicBlock
	instrs   map[Instruction]struct{}
	insane   bool
}

// sanityCheck performs integrity checking of the SSA representation
// of the function fn and returns true if it was valid.  Diagnostics
// are written to reporter if non-nil, os.Stderr otherwise.  Some
// diagnostics are only warnings and do not imply a negative result.
//
// Sanity-checking is intended to facilitate the debugging of code
// transformation passes.
//
func sanityCheck(fn *Function, reporter io.Writer) bool {
	if reporter == nil {
		reporter = os.Stderr
	}
	return (&sanity{reporter: reporter}).checkFunction(fn)
}

// mustSanityCheck is like sanityCheck but panics instead of returning
// a negative result.
//
func mustSanityCheck(fn *Function, reporter io.Writer) {
	if !sanityCheck(fn, reporter) {
		fn.WriteTo(os.Stderr)
		panic("SanityCheck failed")
	}
}

func (s *sanity) diagnostic(prefix, format string, args ...interface{}) {
	fmt.Fprintf(s.reporter, "%s: function %s", prefix, s.fn)
	if s.block != nil {
		fmt.Fprintf(s.reporter, ", block %s", s.block)
	}
	io.WriteString(s.reporter, ": ")
	fmt.Fprintf(s.reporter, format, args...)
	io.WriteString(s.reporter, "\n")
}

func (s *sanity) errorf(format string, args ...interface{}) {
	s.insane = true
	s.diagnostic("Error", format, args...)
}

func (s *sanity) warnf(format string, args ...interface{}) {
	s.diagnostic("Warning", format, args...)
}

// findDuplicate returns an arbitrary basic block that appeared more
// than once in blocks, or nil if all were unique.
func findDuplicate(blocks []*BasicBlock) *BasicBlock {
	if len(blocks) < 2 {
		return nil
	}
	if blocks[0] == blocks[1] {
		return blocks[0]
	}
	// Slow path:
	m := make(map[*BasicBlock]bool)
	for _, b := range blocks {
		if m[b] {
			return b
		}
		m[b] = true
	}
	return nil
}

func (s *sanity) checkInstr(idx int, instr Instruction) {
	switch instr := instr.(type) {
	case *If, *Jump, *Return, *Panic:
		s.errorf("control flow instruction not at end of block")
	case *Phi:
		if idx == 0 {
			// It suffices to apply this check to just the first phi node.
			if dup := findDuplicate(s.block.Preds); dup != nil {
				s.errorf("phi node in block with duplicate predecessor %s", dup)
			}
		} else {
			prev := s.block.Instrs[idx-1]
			if _, ok := prev.(*Phi); !ok {
				s.errorf("Phi instruction follows a non-Phi: %T", prev)
			}
		}
		if ne, np := len(instr.Edges), len(s.block.Preds); ne != np {
			s.errorf("phi node has %d edges but %d predecessors", ne, np)

		} else {
			for i, e := range instr.Edges {
				if e == nil {
					s.errorf("phi node '%s' has no value for edge #%d from %s", instr.Comment, i, s.block.Preds[i])
				}
			}
		}

	case *Alloc:
		if !instr.Heap {
			found := false
			for _, l := range s.fn.Locals {
				if l == instr {
					found = true
					break
				}
			}
			if !found {
				s.errorf("local alloc %s = %s does not appear in Function.Locals", instr.Name(), instr)
			}
		}

	case *BinOp:
	case *Call:
	case *ChangeInterface:
	case *ChangeType:
	case *Convert:
		if _, ok := instr.X.Type().Underlying().(*types.Basic); !ok {
			if _, ok := instr.Type().Underlying().(*types.Basic); !ok {
				s.errorf("convert %s -> %s: at least one type must be basic", instr.X.Type(), instr.Type())
			}
		}

	case *Defer:
	case *Extract:
	case *Field:
	case *FieldAddr:
	case *Go:
	case *Index:
	case *IndexAddr:
	case *Lookup:
	case *MakeChan:
	case *MakeClosure:
		numFree := len(instr.Fn.(*Function).FreeVars)
		numBind := len(instr.Bindings)
		if numFree != numBind {
			s.errorf("MakeClosure has %d Bindings for function %s with %d free vars",
				numBind, instr.Fn, numFree)

		}
		if recv := instr.Type().(*types.Signature).Recv(); recv != nil {
			s.errorf("MakeClosure's type includes receiver %s", recv.Type())
		}

	case *MakeInterface:
	case *MakeMap:
	case *MakeSlice:
	case *MapUpdate:
	case *Next:
	case *Range:
	case *RunDefers:
	case *Select:
	case *Send:
	case *Slice:
	case *Store:
	case *TypeAssert:
	case *UnOp:
	case *DebugRef:
	case *BlankStore:
	case *Sigma:
		// TODO(adonovan): implement checks.
	default:
		panic(fmt.Sprintf("Unknown instruction type: %T", instr))
	}

	if call, ok := instr.(CallInstruction); ok {
		if call.Common().Signature() == nil {
			s.errorf("nil signature: %s", call)
		}
	}

	// Check that value-defining instructions have valid types
	// and a valid referrer list.
	if v, ok := instr.(Value); ok {
		t := v.Type()
		if t == nil {
			s.errorf("no type: %s = %s", v.Name(), v)
		} else if t == tRangeIter {
			// not a proper type; ignore.
		} else if b, ok := t.Underlying().(*types.Basic); ok && b.Info()&types.IsUntyped != 0 {
			s.errorf("instruction has 'untyped' result: %s = %s : %s", v.Name(), v, t)
		}
		s.checkReferrerList(v)
	}

	// Untyped constants are legal as instruction Operands(),
	// for example:
	//   _ = "foo"[0]
	// or:
	//   if wordsize==64 {...}

	// All other non-Instruction Values can be found via their
	// enclosing Function or Package.
}

func (s *sanity) checkFinalInstr(instr Instruction) {
	switch instr := instr.(type) {
	case *If:
		if nsuccs := len(s.block.Succs); nsuccs != 2 {
			s.errorf("If-terminated block has %d successors; expected 2", nsuccs)
			return
		}
		if s.block.Succs[0] == s.block.Succs[1] {
			s.errorf("If-instruction has same True, False target blocks: %s", s.block.Succs[0])
			return
		}

	case *Jump:
		if nsuccs := len(s.block.Succs); nsuccs != 1 {
			s.errorf("Jump-terminated block has %d successors; expected 1", nsuccs)
			return
		}

	case *Return:
		if nsuccs := len(s.block.Succs); nsuccs != 0 {
			s.errorf("Return-terminated block has %d successors; expected none", nsuccs)
			return
		}
		if na, nf := len(instr.Results), s.fn.Signature.Results().Len(); nf != na {
			s.errorf("%d-ary return in %d-ary function", na, nf)
		}

	case *Panic:
		if nsuccs := len(s.block.Succs); nsuccs != 0 {
			s.errorf("Panic-terminated block has %d successors; expected none", nsuccs)
			return
		}

	default:
		s.errorf("non-control flow instruction at end of block")
	}
}

func (s *sanity) checkBlock(b *BasicBlock, index int) {
	s.block = b

	if b.Index != index {
		s.errorf("block has incorrect Index %d", b.Index)
	}
	if b.parent != s.fn {
		s.errorf("block has incorrect parent %s", b.parent)
	}

	// Check all blocks are reachable.
	// (The entry block is always implicitly reachable,
	// as is the Recover block, if any.)
	if (index > 0 && b != b.parent.Recover) && len(b.Preds) == 0 {
		s.warnf("unreachable block")
		if b.Instrs == nil {
			// Since this block is about to be pruned,
			// tolerating transient problems in it
			// simplifies other optimizations.
			return
		}
	}

	// Check predecessor and successor relations are dual,
	// and that all blocks in CFG belong to same function.
	for _, a := range b.Preds {
		found := false
		for _, bb := range a.Succs {
			if bb == b {
				found = true
				break
			}
		}
		if !found {
			s.errorf("expected successor edge in predecessor %s; found only: %s", a, a.Succs)
		}
		if a.parent != s.fn {
			s.errorf("predecessor %s belongs to different function %s", a, a.parent)
		}
	}
	for _, c := range b.Succs {
		found := false
		for _, bb := range c.Preds {
			if bb == b {
				found = true
				break
			}
		}
		if !found {
			s.errorf("expected predecessor edge in successor %s; found only: %s", c, c.Preds)
		}
		if c.parent != s.fn {
			s.errorf("successor %s belongs to different function %s", c, c.parent)
		}
	}

	// Check each instruction is sane.
	n := len(b.Instrs)
	if n == 0 {
		s.errorf("basic block contains no instructions")
	}
	var rands [10]*Value // reuse storage
	for j, instr := range b.Instrs {
		if instr == nil {
			s.errorf("nil instruction at index %d", j)
			continue
		}
		if b2 := instr.Block(); b2 == nil {
			s.errorf("nil Block() for instruction at index %d", j)
			continue
		} else if b2 != b {
			s.errorf("wrong Block() (%s) for instruction at index %d ", b2, j)
			continue
		}
		if j < n-1 {
			s.checkInstr(j, instr)
		} else {
			s.checkFinalInstr(instr)
		}

		// Check Instruction.Operands.
	operands:
		for i, op := range instr.Operands(rands[:0]) {
			if op == nil {
				s.errorf("nil operand pointer %d of %s", i, instr)
				continue
			}
			val := *op
			if val == nil {
				continue // a nil operand is ok
			}

			// Check that "untyped" types only appear on constant operands.
			if _, ok := (*op).(*Const); !ok {
				if basic, ok := (*op).Type().(*types.Basic); ok {
					if basic.Info()&types.IsUntyped != 0 {
						s.errorf("operand #%d of %s is untyped: %s", i, instr, basic)
					}
				}
			}

			// Check that Operands that are also Instructions belong to same function.
			// TODO(adonovan): also check their block dominates block b.
			if val, ok := val.(Instruction); ok {
				if val.Block() == nil {
					s.errorf("operand %d of %s is an instruction (%s) that belongs to no block", i, instr, val)
				} else if val.Parent() != s.fn {
					s.errorf("operand %d of %s is an instruction (%s) from function %s", i, instr, val, val.Parent())
				}
			}

			// Check that each function-local operand of
			// instr refers back to instr.  (NB: quadratic)
			switch val := val.(type) {
			case *Const, *Global, *Builtin:
				continue // not local
			case *Function:
				if val.parent == nil {
					continue // only anon functions are local
				}
			}

			// TODO(adonovan): check val.Parent() != nil <=> val.Referrers() is defined.

			if refs := val.Referrers(); refs != nil {
				for _, ref := range *refs {
					if ref == instr {
						continue operands
					}
				}
				s.errorf("operand %d of %s (%s) does not refer to us", i, instr, val)
			} else {
				s.errorf("operand %d of %s (%s) has no referrers", i, instr, val)
			}
		}
	}
}

func (s *sanity) checkReferrerList(v Value) {
	refs := v.Referrers()
	if refs == nil {
		s.errorf("%s has missing referrer list", v.Name())
		return
	}
	for i, ref := range *refs {
		if _, ok := s.instrs[ref]; !ok {
			s.errorf("%s.Referrers()[%d] = %s is not an instruction belonging to this function", v.Name(), i, ref)
		}
	}
}

func (s *sanity) checkFunction(fn *Function) bool {
	// TODO(adonovan): check Function invariants:
	// - check params match signature
	// - check transient fields are nil
	// - warn if any fn.Locals do not appear among block instructions.
	s.fn = fn
	if fn.Prog == nil {
		s.errorf("nil Prog")
	}

	fn.String()            // must not crash
	fn.RelString(fn.pkg()) // must not crash

	// All functions have a package, except delegates (which are
	// shared across packages, or duplicated as weak symbols in a
	// separate-compilation model), and error.Error.
	if fn.Pkg == nil {
		if strings.HasPrefix(fn.Synthetic, "wrapper ") ||
			strings.HasPrefix(fn.Synthetic, "bound ") ||
			strings.HasPrefix(fn.Synthetic, "thunk ") ||
			strings.HasSuffix(fn.name, "Error") {
			// ok
		} else {
			s.errorf("nil Pkg")
		}
	}
	if src, syn := fn.Synthetic == "", fn.Syntax() != nil; src != syn {
		s.errorf("got fromSource=%t, hasSyntax=%t; want same values", src, syn)
	}
	for i, l := range fn.Locals {
		if l.Parent() != fn {
			s.errorf("Local %s at index %d has wrong parent", l.Name(), i)
		}
		if l.Heap {
			s.errorf("Local %s at index %d has Heap flag set", l.Name(), i)
		}
	}
	// Build the set of valid referrers.
	s.instrs = make(map[Instruction]struct{})
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			s.instrs[instr] = struct{}{}
		}
	}
	for i, p := range fn.Params {
		if p.Parent() != fn {
			s.errorf("Param %s at index %d has wrong parent", p.Name(), i)
		}
		s.checkReferrerList(p)
	}
	for i, fv := range fn.FreeVars {
		if fv.Parent() != fn {
			s.errorf("FreeVar %s at index %d has wrong parent", fv.Name(), i)
		}
		s.checkReferrerList(fv)
	}

	if fn.Blocks != nil && len(fn.Blocks) == 0 {
		// Function _had_ blocks (so it's not external) but
		// they were "optimized" away, even the entry block.
		s.errorf("Blocks slice is non-nil but empty")
	}
	for i, b := range fn.Blocks {
		if b == nil {
			s.warnf("nil *BasicBlock at f.Blocks[%d]", i)
			continue
		}
		s.checkBlock(b, i)
	}
	if fn.Recover != nil && fn.Blocks[fn.Recover.Index] != fn.Recover {
		s.errorf("Recover block is not in Blocks slice")
	}

	s.block = nil
	for i, anon := range fn.AnonFuncs {
		if anon.Parent() != fn {
			s.errorf("AnonFuncs[%d]=%s but %s.Parent()=%s", i, anon, anon, anon.Parent())
		}
	}
	s.fn = nil
	return !s.insane
}

// sanityCheckPackage checks invariants of packages upon creation.
// It does not require that the package is built.
// Unlike sanityCheck (for functions), it just panics at the first error.
func sanityCheckPackage(pkg *Package) {
	if pkg.Pkg == nil {
		panic(fmt.Sprintf("Package %s has no Object", pkg))
	}
	pkg.String() // must not crash

	for name, mem := range pkg.Members {
		if name != mem.Name() {
			panic(fmt.Sprintf("%s: %T.Name() = %s, want %s",
				pkg.Pkg.Path(), mem, mem.Name(), name))
		}
		obj := mem.Object()
		if obj == nil {
			// This check is sound because fields
			// {Global,Function}.object have type
			// types.Object.  (If they were declared as
			// *types.{Var,Func}, we'd have a non-empty
			// interface containing a nil pointer.)

			continue // not all members have typechecker objects
		}
		if obj.Name() != name {
			if obj.Name() == "init" && strings.HasPrefix(mem.Name(), "init#") {
				// Ok.  The name of a declared init function varies between
				// its types.Func ("init") and its ssa.Function ("init#%d").
			} else {
				panic(fmt.Sprintf("%s: %T.Object().Name() = %s, want %s",
					pkg.Pkg.Path(), mem, obj.Name(), name))
			}
		}
		if obj.Pos() != mem.Pos() {
			panic(fmt.Sprintf("%s Pos=%d obj.Pos=%d", mem, mem.Pos(), obj.Pos()))
		}
	}
}

"""



```