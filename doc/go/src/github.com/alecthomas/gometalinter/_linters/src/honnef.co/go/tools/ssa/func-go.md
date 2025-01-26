Response:
The user wants to understand the functionality of the provided Go code snippet, which is part of the `ssa` package in the `honnef.co/go/tools` library. The code defines the `Function` and `BasicBlock` types, which are core components in Static Single Assignment (SSA) representation of Go code.

Here's a plan to address the user's request:

1. **Identify the main purpose of the code:** It defines the structure for representing functions and their basic blocks in SSA form.
2. **List the key functionalities related to `BasicBlock`:**  Explain methods like `Parent`, `String`, `emit`, `predIndex`, `hasPhi`, `Phis`, `replacePred`, `replaceSucc`, and `removePred`.
3. **List the key functionalities related to `Function`:** Explain methods related to parameter handling (`addParam`, `addParamObj`, `addSpilledParam`, `createSyntacticParams`), basic block management (`newBasicBlock`), local variable management (`addNamedLocal`, `addLocal`, `lookup`), control flow graph management (`labelledBlock`), and output/debugging (`WriteTo`, `RelString`). Also cover methods related to the overall SSA construction process (`startBody`, `finishBody`, `removeNilBlocks`).
4. **Provide Go code examples:** Demonstrate how some of the key methods of `BasicBlock` and `Function` are used in practice. This will involve creating a simple function and manipulating its blocks and instructions.
5. **Address potential areas of confusion:**  Explain aspects of SSA that might be tricky for users, such as the role of Phi nodes and the concept of spilling parameters.
6. **Explain the command-line context (if any):**  Although the provided snippet itself doesn't directly handle command-line arguments, it's part of a larger tool. Mention that this code is a building block for static analysis tools, which often have command-line interfaces. Highlight that the `Program` type (mentioned in the code) likely handles program-wide settings, potentially influenced by command-line flags.
这段Go语言代码是 `ssa` 包的一部分，该包用于构建和操作 Go 程序的静态单赋值形式 (Static Single Assignment, SSA)。它主要定义了 `Function` 和 `BasicBlock` 这两个核心类型，用于表示函数的控制流图。

以下是代码的主要功能：

**1. `BasicBlock` 结构体及其方法：**

* **表示基本块:** `BasicBlock` 代表控制流图中的一个基本块，它是一系列顺序执行的指令序列，没有内部的分支。
* **`Parent() *Function`:** 返回包含该基本块的函数。
* **`String() string`:** 返回该基本块的可读标签（通常是其索引）。
* **`emit(i Instruction) Value`:** 向当前基本块追加一条指令。如果该指令定义了一个值（实现了 `Value` 接口），则返回该值。
* **`predIndex(c *BasicBlock) int`:** 返回该基本块的前驱块 `c` 在其前驱列表中的索引。如果 `c` 不是前驱，则会 panic。
* **`hasPhi() bool`:** 检查该基本块是否包含 φ-节点 (Phi nodes)。φ-节点用于在控制流汇合处合并来自不同前驱块的值。
* **`Phis() []Instruction` 和 `phis() []Instruction`:** 返回该基本块中所有 φ-节点的切片。
* **`replacePred(p, q *BasicBlock)`:** 将该基本块前驱列表中所有出现的块 `p` 替换为块 `q`。
* **`replaceSucc(p, q *BasicBlock)`:** 将该基本块后继列表中所有出现的块 `p` 替换为块 `q`。
* **`RemovePred(p *BasicBlock)` 和 `removePred(p *BasicBlock)`:** 从该基本块的前驱列表和 φ-节点中移除所有出现的块 `p`。  需要维护 φ-节点的边顺序。

**2. `Function` 结构体及其方法：**

* **表示函数:** `Function` 代表一个 Go 函数的 SSA 表示。
* **控制流图构建:**
    * **`newBasicBlock(comment string) *BasicBlock`:** 创建并添加一个新的基本块到函数中。
    * **`addEdge(from, to *BasicBlock)`:**  添加从 `from` 基本块到 `to` 基本块的控制流边。
* **参数处理:**
    * **`addParam(name string, typ types.Type, pos token.Pos) *Parameter`:** 添加一个非逃逸的参数到函数的参数列表中。
    * **`addParamObj(obj types.Object) *Parameter`:**  根据 `types.Object` 添加参数。
    * **`addSpilledParam(obj types.Object)`:** 声明一个预先溢出到栈上的参数。
    * **`createSyntacticParams(recv *ast.FieldList, functype *ast.FuncType)`:**  根据语法树中的参数声明创建函数的参数。
* **局部变量管理:**
    * **`addNamedLocal(obj types.Object) *Alloc`:** 创建一个命名的局部变量。
    * **`addLocalForIdent(id *ast.Ident) *Alloc`:**  根据 `ast.Ident` 创建局部变量。
    * **`addLocal(typ types.Type, pos token.Pos) *Alloc`:** 创建一个匿名局部变量。
    * **`lookup(obj types.Object, escaping bool) Value`:**  查找本地或外层函数中定义的变量。
* **控制流目标:**
    * **`labelledBlock(label *ast.Ident) *lblock`:** 获取与指定标签关联的分支目标基本块，如果不存在则创建。
* **SSA 构建的生命周期管理:**
    * **`startBody()`:** 初始化函数，为生成 SSA 代码做准备。
    * **`finishBody()`:** 完成函数 SSA 代码的生成，进行一些优化和清理工作。
    * **`removeNilBlocks()`:**  移除 `f.Blocks` 中的 `nil` 值，并更新基本块的索引。
* **调试和输出:**
    * **`numberRegisters(f *Function)`:** 为函数中的所有 SSA 寄存器（定义值的指令）分配编号，用于调试。
    * **`WriteTo(w io.Writer) (int64, error)` 和 `WriteFunction(buf *bytes.Buffer, f *Function)`:** 将函数的 SSA 表示以可读的格式写入到 `io.Writer` 或 `bytes.Buffer` 中。
    * **`RelString(from *types.Package) string`:** 返回函数的完整名称，可以指定引用的包，用于跨包引用时显示完整的路径。
* **其他:**
    * **`SetDebugMode(debug bool)` (在 `Package` 类型上):** 设置包的调试模式，如果为 `true`，则函数会包含完整的调试信息。
    * **`debugInfo() bool`:**  报告是否为该函数生成调试信息。
    * **`Syntax() ast.Node`:** 返回函数的语法树节点。
    * **`NewFunction(name string, sig *types.Signature, provenance string) *Function` (在 `Program` 类型上):** 创建一个新的合成 `Function` 实例。

**代码推理示例：实现 `if` 语句**

假设我们要为一个简单的 `if` 语句生成 SSA 代码：

```go
package main

func foo(x int) int {
	if x > 10 {
		return x * 2
	}
	return x + 1
}
```

**假设的输入（`Function` 对象 `f` 已经创建并初始化，参数 `x` 已经处理）：**

* `f.currentBlock` 指向 `entry` 基本块。
* 参数 `x` 对应的 `ssa.Value` 对象已创建。
* 常量 `10` 和 `2` 对应的 `ssa.Value` 对象已创建。

**生成的 SSA 代码片段（简化）：**

```
entry:
  t0 = GreaterThan x #int 10 #int
  If t0 block_true block_false

block_true:
  t1 = BinOp x * #int 2 #int
  Ret t1

block_false:
  t2 = BinOp x + #int 1 #int
  Ret t2
```

**对应的 `func.go` 代码调用流程（简化）：**

1. **比较操作:**  生成比较指令 `GreaterThan` 并添加到 `entry` 块。
   ```go
   cond := f.emit(&BinOp{Op: token.GTR, X: xValue, Y: const10Value})
   ```
2. **创建分支块:** 创建 `block_true` 和 `block_false` 两个新的基本块。
   ```go
   trueBlock := f.newBasicBlock("if.true")
   falseBlock := f.newBasicBlock("if.false")
   ```
3. **生成条件分支指令:** 生成 `If` 指令，根据比较结果跳转到相应的块。
   ```go
   f.emit(&If{Cond: cond, True: trueBlock, False: falseBlock})
   ```
4. **处理 `true` 分支:** 将当前块设置为 `block_true`，生成乘法操作和 `Ret` 指令。
   ```go
   f.currentBlock = trueBlock
   multResult := f.emit(&BinOp{Op: token.MUL, X: xValue, Y: const2Value})
   f.emit(&Return{Results: []Value{multResult}})
   ```
5. **处理 `false` 分支:** 将当前块设置为 `block_false`，生成加法操作和 `Ret` 指令。
   ```go
   f.currentBlock = falseBlock
   addResult := f.emit(&BinOp{Op: token.ADD, X: xValue, Y: const1Value})
   f.emit(&Return{Results: []Value{addResult}})
   ```

**假设的输出：** 上述生成的 SSA 代码片段。

**命令行参数的具体处理：**

这段代码本身并不直接处理命令行参数。但是，`ssa` 包通常是更大型的静态分析工具的一部分，这些工具可能会接受命令行参数来控制分析的行为，例如：

* **指定要分析的 Go 包或文件。**
* **开启或关闭特定的分析 passes 或优化。**
* **设置调试级别，控制输出的详细程度。**

`Program` 类型（在代码中出现）很可能负责管理程序级别的设置，这些设置可能会受到命令行参数的影响。例如，`prog.mode` 字段可能通过命令行参数设置，控制是否进行某些优化 (`NaiveForm == 0`) 或输出函数信息 (`PrintFunctions != 0`).

**使用者易犯错的点：**

* **手动修改 SSA 图:** 用户通常不应该直接手动修改 `Function` 和 `BasicBlock` 的结构（例如，直接修改 `Preds` 或 `Succs` 列表）。 应该使用 `ssa` 包提供的 API 方法（如 `addEdge`, `replacePred`, `removePred`）来确保 SSA 图的一致性。错误的修改可能导致后续的分析或优化 pass 出现不可预测的行为甚至崩溃。
* **不理解 Phi 节点的作用:**  φ-节点是 SSA 的核心概念，用于处理控制流汇合处的值合并。不理解 φ-节点及其如何正确插入和更新可能会导致对 SSA 表示的误解。例如，忘记在需要的地方插入 φ-节点，或者错误地连接 φ-节点的输入边，都会导致 SSA 表示不正确。

**示例说明手动修改可能导致的问题：**

假设一个基本块 `B` 有两个前驱 `A1` 和 `A2`，并且包含一个使用了来自这两个前驱的值的 φ-节点。如果用户直接修改 `B.Preds` 列表，但没有相应地更新 φ-节点的 `Edges` 列表，那么 φ-节点将引用错误的输入值，导致 SSA 表示不一致。

总而言之，这段代码是构建 Go 程序 SSA 表示的基础，提供了操作函数和基本块的各种方法，为后续的静态分析和优化提供了数据结构和操作接口。用户应该通过 `ssa` 包提供的接口来操作 SSA 图，而不是直接修改其内部结构。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/func.go的go语言实现的一部分， 请列举一下它的功能, 　
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

// This file implements the Function and BasicBlock types.

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io"
	"os"
	"strings"
)

// addEdge adds a control-flow graph edge from from to to.
func addEdge(from, to *BasicBlock) {
	from.Succs = append(from.Succs, to)
	to.Preds = append(to.Preds, from)
}

// Parent returns the function that contains block b.
func (b *BasicBlock) Parent() *Function { return b.parent }

// String returns a human-readable label of this block.
// It is not guaranteed unique within the function.
//
func (b *BasicBlock) String() string {
	return fmt.Sprintf("%d", b.Index)
}

// emit appends an instruction to the current basic block.
// If the instruction defines a Value, it is returned.
//
func (b *BasicBlock) emit(i Instruction) Value {
	i.setBlock(b)
	b.Instrs = append(b.Instrs, i)
	v, _ := i.(Value)
	return v
}

// predIndex returns the i such that b.Preds[i] == c or panics if
// there is none.
func (b *BasicBlock) predIndex(c *BasicBlock) int {
	for i, pred := range b.Preds {
		if pred == c {
			return i
		}
	}
	panic(fmt.Sprintf("no edge %s -> %s", c, b))
}

// hasPhi returns true if b.Instrs contains φ-nodes.
func (b *BasicBlock) hasPhi() bool {
	_, ok := b.Instrs[0].(*Phi)
	return ok
}

func (b *BasicBlock) Phis() []Instruction {
	return b.phis()
}

// phis returns the prefix of b.Instrs containing all the block's φ-nodes.
func (b *BasicBlock) phis() []Instruction {
	for i, instr := range b.Instrs {
		if _, ok := instr.(*Phi); !ok {
			return b.Instrs[:i]
		}
	}
	return nil // unreachable in well-formed blocks
}

// replacePred replaces all occurrences of p in b's predecessor list with q.
// Ordinarily there should be at most one.
//
func (b *BasicBlock) replacePred(p, q *BasicBlock) {
	for i, pred := range b.Preds {
		if pred == p {
			b.Preds[i] = q
		}
	}
}

// replaceSucc replaces all occurrences of p in b's successor list with q.
// Ordinarily there should be at most one.
//
func (b *BasicBlock) replaceSucc(p, q *BasicBlock) {
	for i, succ := range b.Succs {
		if succ == p {
			b.Succs[i] = q
		}
	}
}

func (b *BasicBlock) RemovePred(p *BasicBlock) {
	b.removePred(p)
}

// removePred removes all occurrences of p in b's
// predecessor list and φ-nodes.
// Ordinarily there should be at most one.
//
func (b *BasicBlock) removePred(p *BasicBlock) {
	phis := b.phis()

	// We must preserve edge order for φ-nodes.
	j := 0
	for i, pred := range b.Preds {
		if pred != p {
			b.Preds[j] = b.Preds[i]
			// Strike out φ-edge too.
			for _, instr := range phis {
				phi := instr.(*Phi)
				phi.Edges[j] = phi.Edges[i]
			}
			j++
		}
	}
	// Nil out b.Preds[j:] and φ-edges[j:] to aid GC.
	for i := j; i < len(b.Preds); i++ {
		b.Preds[i] = nil
		for _, instr := range phis {
			instr.(*Phi).Edges[i] = nil
		}
	}
	b.Preds = b.Preds[:j]
	for _, instr := range phis {
		phi := instr.(*Phi)
		phi.Edges = phi.Edges[:j]
	}
}

// Destinations associated with unlabelled for/switch/select stmts.
// We push/pop one of these as we enter/leave each construct and for
// each BranchStmt we scan for the innermost target of the right type.
//
type targets struct {
	tail         *targets // rest of stack
	_break       *BasicBlock
	_continue    *BasicBlock
	_fallthrough *BasicBlock
}

// Destinations associated with a labelled block.
// We populate these as labels are encountered in forward gotos or
// labelled statements.
//
type lblock struct {
	_goto     *BasicBlock
	_break    *BasicBlock
	_continue *BasicBlock
}

// labelledBlock returns the branch target associated with the
// specified label, creating it if needed.
//
func (f *Function) labelledBlock(label *ast.Ident) *lblock {
	lb := f.lblocks[label.Obj]
	if lb == nil {
		lb = &lblock{_goto: f.newBasicBlock(label.Name)}
		if f.lblocks == nil {
			f.lblocks = make(map[*ast.Object]*lblock)
		}
		f.lblocks[label.Obj] = lb
	}
	return lb
}

// addParam adds a (non-escaping) parameter to f.Params of the
// specified name, type and source position.
//
func (f *Function) addParam(name string, typ types.Type, pos token.Pos) *Parameter {
	v := &Parameter{
		name:   name,
		typ:    typ,
		pos:    pos,
		parent: f,
	}
	f.Params = append(f.Params, v)
	return v
}

func (f *Function) addParamObj(obj types.Object) *Parameter {
	name := obj.Name()
	if name == "" {
		name = fmt.Sprintf("arg%d", len(f.Params))
	}
	param := f.addParam(name, obj.Type(), obj.Pos())
	param.object = obj
	return param
}

// addSpilledParam declares a parameter that is pre-spilled to the
// stack; the function body will load/store the spilled location.
// Subsequent lifting will eliminate spills where possible.
//
func (f *Function) addSpilledParam(obj types.Object) {
	param := f.addParamObj(obj)
	spill := &Alloc{Comment: obj.Name()}
	spill.setType(types.NewPointer(obj.Type()))
	spill.setPos(obj.Pos())
	f.objects[obj] = spill
	f.Locals = append(f.Locals, spill)
	f.emit(spill)
	f.emit(&Store{Addr: spill, Val: param})
}

// startBody initializes the function prior to generating SSA code for its body.
// Precondition: f.Type() already set.
//
func (f *Function) startBody() {
	f.currentBlock = f.newBasicBlock("entry")
	f.objects = make(map[types.Object]Value) // needed for some synthetics, e.g. init
}

// createSyntacticParams populates f.Params and generates code (spills
// and named result locals) for all the parameters declared in the
// syntax.  In addition it populates the f.objects mapping.
//
// Preconditions:
// f.startBody() was called.
// Postcondition:
// len(f.Params) == len(f.Signature.Params) + (f.Signature.Recv() ? 1 : 0)
//
func (f *Function) createSyntacticParams(recv *ast.FieldList, functype *ast.FuncType) {
	// Receiver (at most one inner iteration).
	if recv != nil {
		for _, field := range recv.List {
			for _, n := range field.Names {
				f.addSpilledParam(f.Pkg.info.Defs[n])
			}
			// Anonymous receiver?  No need to spill.
			if field.Names == nil {
				f.addParamObj(f.Signature.Recv())
			}
		}
	}

	// Parameters.
	if functype.Params != nil {
		n := len(f.Params) // 1 if has recv, 0 otherwise
		for _, field := range functype.Params.List {
			for _, n := range field.Names {
				f.addSpilledParam(f.Pkg.info.Defs[n])
			}
			// Anonymous parameter?  No need to spill.
			if field.Names == nil {
				f.addParamObj(f.Signature.Params().At(len(f.Params) - n))
			}
		}
	}

	// Named results.
	if functype.Results != nil {
		for _, field := range functype.Results.List {
			// Implicit "var" decl of locals for named results.
			for _, n := range field.Names {
				f.namedResults = append(f.namedResults, f.addLocalForIdent(n))
			}
		}
	}
}

// numberRegisters assigns numbers to all SSA registers
// (value-defining Instructions) in f, to aid debugging.
// (Non-Instruction Values are named at construction.)
//
func numberRegisters(f *Function) {
	v := 0
	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			switch instr.(type) {
			case Value:
				instr.(interface {
					setNum(int)
				}).setNum(v)
				v++
			}
		}
	}
}

// buildReferrers populates the def/use information in all non-nil
// Value.Referrers slice.
// Precondition: all such slices are initially empty.
func buildReferrers(f *Function) {
	var rands []*Value
	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			rands = instr.Operands(rands[:0]) // recycle storage
			for _, rand := range rands {
				if r := *rand; r != nil {
					if ref := r.Referrers(); ref != nil {
						*ref = append(*ref, instr)
					}
				}
			}
		}
	}
}

// finishBody() finalizes the function after SSA code generation of its body.
func (f *Function) finishBody() {
	f.objects = nil
	f.currentBlock = nil
	f.lblocks = nil

	// Don't pin the AST in memory (except in debug mode).
	if n := f.syntax; n != nil && !f.debugInfo() {
		f.syntax = extentNode{n.Pos(), n.End()}
	}

	// Remove from f.Locals any Allocs that escape to the heap.
	j := 0
	for _, l := range f.Locals {
		if !l.Heap {
			f.Locals[j] = l
			j++
		}
	}
	// Nil out f.Locals[j:] to aid GC.
	for i := j; i < len(f.Locals); i++ {
		f.Locals[i] = nil
	}
	f.Locals = f.Locals[:j]

	optimizeBlocks(f)

	buildReferrers(f)

	buildDomTree(f)

	if f.Prog.mode&NaiveForm == 0 {
		// For debugging pre-state of lifting pass:
		// numberRegisters(f)
		// f.WriteTo(os.Stderr)
		lift(f)
	}

	f.namedResults = nil // (used by lifting)

	numberRegisters(f)

	if f.Prog.mode&PrintFunctions != 0 {
		printMu.Lock()
		f.WriteTo(os.Stdout)
		printMu.Unlock()
	}

	if f.Prog.mode&SanityCheckFunctions != 0 {
		mustSanityCheck(f, nil)
	}
}

func (f *Function) RemoveNilBlocks() {
	f.removeNilBlocks()
}

// removeNilBlocks eliminates nils from f.Blocks and updates each
// BasicBlock.Index.  Use this after any pass that may delete blocks.
//
func (f *Function) removeNilBlocks() {
	j := 0
	for _, b := range f.Blocks {
		if b != nil {
			b.Index = j
			f.Blocks[j] = b
			j++
		}
	}
	// Nil out f.Blocks[j:] to aid GC.
	for i := j; i < len(f.Blocks); i++ {
		f.Blocks[i] = nil
	}
	f.Blocks = f.Blocks[:j]
}

// SetDebugMode sets the debug mode for package pkg.  If true, all its
// functions will include full debug info.  This greatly increases the
// size of the instruction stream, and causes Functions to depend upon
// the ASTs, potentially keeping them live in memory for longer.
//
func (pkg *Package) SetDebugMode(debug bool) {
	// TODO(adonovan): do we want ast.File granularity?
	pkg.debug = debug
}

// debugInfo reports whether debug info is wanted for this function.
func (f *Function) debugInfo() bool {
	return f.Pkg != nil && f.Pkg.debug
}

// addNamedLocal creates a local variable, adds it to function f and
// returns it.  Its name and type are taken from obj.  Subsequent
// calls to f.lookup(obj) will return the same local.
//
func (f *Function) addNamedLocal(obj types.Object) *Alloc {
	l := f.addLocal(obj.Type(), obj.Pos())
	l.Comment = obj.Name()
	f.objects[obj] = l
	return l
}

func (f *Function) addLocalForIdent(id *ast.Ident) *Alloc {
	return f.addNamedLocal(f.Pkg.info.Defs[id])
}

// addLocal creates an anonymous local variable of type typ, adds it
// to function f and returns it.  pos is the optional source location.
//
func (f *Function) addLocal(typ types.Type, pos token.Pos) *Alloc {
	v := &Alloc{}
	v.setType(types.NewPointer(typ))
	v.setPos(pos)
	f.Locals = append(f.Locals, v)
	f.emit(v)
	return v
}

// lookup returns the address of the named variable identified by obj
// that is local to function f or one of its enclosing functions.
// If escaping, the reference comes from a potentially escaping pointer
// expression and the referent must be heap-allocated.
//
func (f *Function) lookup(obj types.Object, escaping bool) Value {
	if v, ok := f.objects[obj]; ok {
		if alloc, ok := v.(*Alloc); ok && escaping {
			alloc.Heap = true
		}
		return v // function-local var (address)
	}

	// Definition must be in an enclosing function;
	// plumb it through intervening closures.
	if f.parent == nil {
		panic("no ssa.Value for " + obj.String())
	}
	outer := f.parent.lookup(obj, true) // escaping
	v := &FreeVar{
		name:   obj.Name(),
		typ:    outer.Type(),
		pos:    outer.Pos(),
		outer:  outer,
		parent: f,
	}
	f.objects[obj] = v
	f.FreeVars = append(f.FreeVars, v)
	return v
}

// emit emits the specified instruction to function f.
func (f *Function) emit(instr Instruction) Value {
	return f.currentBlock.emit(instr)
}

// RelString returns the full name of this function, qualified by
// package name, receiver type, etc.
//
// The specific formatting rules are not guaranteed and may change.
//
// Examples:
//      "math.IsNaN"                  // a package-level function
//      "(*bytes.Buffer).Bytes"       // a declared method or a wrapper
//      "(*bytes.Buffer).Bytes$thunk" // thunk (func wrapping method; receiver is param 0)
//      "(*bytes.Buffer).Bytes$bound" // bound (func wrapping method; receiver supplied by closure)
//      "main.main$1"                 // an anonymous function in main
//      "main.init#1"                 // a declared init function
//      "main.init"                   // the synthesized package initializer
//
// When these functions are referred to from within the same package
// (i.e. from == f.Pkg.Object), they are rendered without the package path.
// For example: "IsNaN", "(*Buffer).Bytes", etc.
//
// All non-synthetic functions have distinct package-qualified names.
// (But two methods may have the same name "(T).f" if one is a synthetic
// wrapper promoting a non-exported method "f" from another package; in
// that case, the strings are equal but the identifiers "f" are distinct.)
//
func (f *Function) RelString(from *types.Package) string {
	// Anonymous?
	if f.parent != nil {
		// An anonymous function's Name() looks like "parentName$1",
		// but its String() should include the type/package/etc.
		parent := f.parent.RelString(from)
		for i, anon := range f.parent.AnonFuncs {
			if anon == f {
				return fmt.Sprintf("%s$%d", parent, 1+i)
			}
		}

		return f.name // should never happen
	}

	// Method (declared or wrapper)?
	if recv := f.Signature.Recv(); recv != nil {
		return f.relMethod(from, recv.Type())
	}

	// Thunk?
	if f.method != nil {
		return f.relMethod(from, f.method.Recv())
	}

	// Bound?
	if len(f.FreeVars) == 1 && strings.HasSuffix(f.name, "$bound") {
		return f.relMethod(from, f.FreeVars[0].Type())
	}

	// Package-level function?
	// Prefix with package name for cross-package references only.
	if p := f.pkg(); p != nil && p != from {
		return fmt.Sprintf("%s.%s", p.Path(), f.name)
	}

	// Unknown.
	return f.name
}

func (f *Function) relMethod(from *types.Package, recv types.Type) string {
	return fmt.Sprintf("(%s).%s", relType(recv, from), f.name)
}

// writeSignature writes to buf the signature sig in declaration syntax.
func writeSignature(buf *bytes.Buffer, from *types.Package, name string, sig *types.Signature, params []*Parameter) {
	buf.WriteString("func ")
	if recv := sig.Recv(); recv != nil {
		buf.WriteString("(")
		if n := params[0].Name(); n != "" {
			buf.WriteString(n)
			buf.WriteString(" ")
		}
		types.WriteType(buf, params[0].Type(), types.RelativeTo(from))
		buf.WriteString(") ")
	}
	buf.WriteString(name)
	types.WriteSignature(buf, sig, types.RelativeTo(from))
}

func (f *Function) pkg() *types.Package {
	if f.Pkg != nil {
		return f.Pkg.Pkg
	}
	return nil
}

var _ io.WriterTo = (*Function)(nil) // *Function implements io.Writer

func (f *Function) WriteTo(w io.Writer) (int64, error) {
	var buf bytes.Buffer
	WriteFunction(&buf, f)
	n, err := w.Write(buf.Bytes())
	return int64(n), err
}

// WriteFunction writes to buf a human-readable "disassembly" of f.
func WriteFunction(buf *bytes.Buffer, f *Function) {
	fmt.Fprintf(buf, "# Name: %s\n", f.String())
	if f.Pkg != nil {
		fmt.Fprintf(buf, "# Package: %s\n", f.Pkg.Pkg.Path())
	}
	if syn := f.Synthetic; syn != "" {
		fmt.Fprintln(buf, "# Synthetic:", syn)
	}
	if pos := f.Pos(); pos.IsValid() {
		fmt.Fprintf(buf, "# Location: %s\n", f.Prog.Fset.Position(pos))
	}

	if f.parent != nil {
		fmt.Fprintf(buf, "# Parent: %s\n", f.parent.Name())
	}

	if f.Recover != nil {
		fmt.Fprintf(buf, "# Recover: %s\n", f.Recover)
	}

	from := f.pkg()

	if f.FreeVars != nil {
		buf.WriteString("# Free variables:\n")
		for i, fv := range f.FreeVars {
			fmt.Fprintf(buf, "# % 3d:\t%s %s\n", i, fv.Name(), relType(fv.Type(), from))
		}
	}

	if len(f.Locals) > 0 {
		buf.WriteString("# Locals:\n")
		for i, l := range f.Locals {
			fmt.Fprintf(buf, "# % 3d:\t%s %s\n", i, l.Name(), relType(deref(l.Type()), from))
		}
	}
	writeSignature(buf, from, f.Name(), f.Signature, f.Params)
	buf.WriteString(":\n")

	if f.Blocks == nil {
		buf.WriteString("\t(external)\n")
	}

	// NB. column calculations are confused by non-ASCII
	// characters and assume 8-space tabs.
	const punchcard = 80 // for old time's sake.
	const tabwidth = 8
	for _, b := range f.Blocks {
		if b == nil {
			// Corrupt CFG.
			fmt.Fprintf(buf, ".nil:\n")
			continue
		}
		n, _ := fmt.Fprintf(buf, "%d:", b.Index)
		bmsg := fmt.Sprintf("%s P:%d S:%d", b.Comment, len(b.Preds), len(b.Succs))
		fmt.Fprintf(buf, "%*s%s\n", punchcard-1-n-len(bmsg), "", bmsg)

		if false { // CFG debugging
			fmt.Fprintf(buf, "\t# CFG: %s --> %s --> %s\n", b.Preds, b, b.Succs)
		}
		for _, instr := range b.Instrs {
			buf.WriteString("\t")
			switch v := instr.(type) {
			case Value:
				l := punchcard - tabwidth
				// Left-align the instruction.
				if name := v.Name(); name != "" {
					n, _ := fmt.Fprintf(buf, "%s = ", name)
					l -= n
				}
				n, _ := buf.WriteString(instr.String())
				l -= n
				// Right-align the type if there's space.
				if t := v.Type(); t != nil {
					buf.WriteByte(' ')
					ts := relType(t, from)
					l -= len(ts) + len("  ") // (spaces before and after type)
					if l > 0 {
						fmt.Fprintf(buf, "%*s", l, "")
					}
					buf.WriteString(ts)
				}
			case nil:
				// Be robust against bad transforms.
				buf.WriteString("<deleted>")
			default:
				buf.WriteString(instr.String())
			}
			buf.WriteString("\n")
		}
	}
	fmt.Fprintf(buf, "\n")
}

// newBasicBlock adds to f a new basic block and returns it.  It does
// not automatically become the current block for subsequent calls to emit.
// comment is an optional string for more readable debugging output.
//
func (f *Function) newBasicBlock(comment string) *BasicBlock {
	b := &BasicBlock{
		Index:   len(f.Blocks),
		Comment: comment,
		parent:  f,
	}
	b.Succs = b.succs2[:0]
	f.Blocks = append(f.Blocks, b)
	return b
}

// NewFunction returns a new synthetic Function instance belonging to
// prog, with its name and signature fields set as specified.
//
// The caller is responsible for initializing the remaining fields of
// the function object, e.g. Pkg, Params, Blocks.
//
// It is practically impossible for clients to construct well-formed
// SSA functions/packages/programs directly, so we assume this is the
// job of the Builder alone.  NewFunction exists to provide clients a
// little flexibility.  For example, analysis tools may wish to
// construct fake Functions for the root of the callgraph, a fake
// "reflect" package, etc.
//
// TODO(adonovan): think harder about the API here.
//
func (prog *Program) NewFunction(name string, sig *types.Signature, provenance string) *Function {
	return &Function{Prog: prog, name: name, Signature: sig, Synthetic: provenance}
}

type extentNode [2]token.Pos

func (n extentNode) Pos() token.Pos { return n[0] }
func (n extentNode) End() token.Pos { return n[1] }

// Syntax returns an ast.Node whose Pos/End methods provide the
// lexical extent of the function if it was defined by Go source code
// (f.Synthetic==""), or nil otherwise.
//
// If f was built with debug information (see Package.SetDebugRef),
// the result is the *ast.FuncDecl or *ast.FuncLit that declared the
// function.  Otherwise, it is an opaque Node providing only position
// information; this avoids pinning the AST in memory.
//
func (f *Function) Syntax() ast.Node { return f.syntax }

"""



```