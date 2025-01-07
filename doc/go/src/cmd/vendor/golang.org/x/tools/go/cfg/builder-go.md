Response:
Let's break down the thought process to analyze the provided Go code snippet.

**1. Initial Reading and Understanding the Context:**

The first step is to read through the code to get a general idea of what it's doing. The package name `cfg` and the file name `builder.go` within `golang.org/x/tools/go/cfg` strongly suggest this code is responsible for building Control Flow Graphs (CFGs). The comments at the beginning confirm this.

**2. Identifying Key Data Structures:**

Next, I look for the core data structures. The `builder` struct is clearly central, containing fields like `cfg`, `current`, `lblocks`, and `targets`. I then examine the types of these fields:

* `cfg *CFG`:  This confirms the CFG building purpose. It likely holds the overall CFG being constructed.
* `current *Block`: This probably represents the block of code currently being processed.
* `lblocks map[string]*lblock`: This suggests handling labeled statements and their associated blocks. The `lblock` struct itself reinforces this.
* `targets *targets`: This seems to manage targets for `break`, `continue`, and `fallthrough` statements within loops and switches. The `targets` struct confirms this.

**3. Analyzing the Core Logic - The `stmt` Function:**

The `stmt` function is the heart of the builder. Its structure is a large `switch` statement based on the type of Go statement (`ast.Stmt`). This immediately tells me the code processes different statement types differently to build the CFG.

**4. Deconstructing the `stmt` Switch Cases:**

I then go through each case in the `stmt` switch, trying to understand how it handles the control flow for that particular statement type:

* **Simple Statements (`BadStmt`, `SendStmt`, etc.):**  These seem to have straightforward control flow, simply adding the statement to the current block (`b.add(s)`). The `ExprStmt` case has an interesting check for non-returning calls.
* **`DeclStmt`:** This shows how variable declarations are handled.
* **`LabeledStmt`:** This confirms the purpose of `lblocks`, creating and jumping to labeled blocks. The `goto start` suggests a form of tail-call optimization within the function.
* **`ReturnStmt`:**  Clearly marks the end of a function's execution path.
* **`BranchStmt`:** This is where `break`, `continue`, `fallthrough`, and `goto` are handled, leveraging the `targets` and `lblocks` structures.
* **`BlockStmt`:** Processes a list of statements sequentially.
* **`IfStmt`:** This clearly outlines how `if-else` control flow is translated into CFG blocks and edges.
* **`SwitchStmt` and `TypeSwitchStmt`:** These are more complex, showing how different cases and the `fallthrough` behavior are managed in the CFG.
* **`SelectStmt`:** Handles the complexities of `select` statements, particularly with channel operations.
* **`ForStmt` and `RangeStmt`:** These demonstrate how loops are represented in the CFG, including `break` and `continue` targets.

**5. Inferring Functionality and Providing Examples:**

Based on the analysis of `stmt` and the supporting functions (`stmtList`, `branchStmt`, etc.), I can infer the primary function: building a Control Flow Graph from Go source code.

To illustrate this, I choose a simple `if` statement and trace how the `builder` would handle it, creating the necessary blocks and edges. I provide the Go code and a textual representation of the expected CFG.

**6. Considering Command-Line Arguments:**

Since this code is part of the `go/analysis` toolchain, it's likely used by other tools that might have command-line arguments. However, this specific code snippet doesn't directly handle command-line arguments. It's a building block. Therefore, I explain this distinction.

**7. Identifying Potential Pitfalls:**

I review the code for areas where a user (likely a developer working on or using the `go/analysis` tools) might make mistakes:

* **Incorrectly handling `fallthrough` in `switch` statements:** The way `fallthrough` jumps to the *next* case's body can be counterintuitive.
* **Misunderstanding the scope of `break` and `continue`:**  These statements apply to the innermost loop or `switch`/`select` by default. Labeled breaks/continues are needed for outer constructs.
* **Forgetting `break` in `switch` cases:** Leading to unintended fallthrough.

I then provide code examples to illustrate these common mistakes.

**8. Review and Refinement:**

Finally, I reread my analysis and examples to ensure accuracy, clarity, and completeness. I check if the explanations logically follow from the code and if the examples are helpful. For example, I make sure the CFG diagram for the `if` statement accurately reflects the code.

This step-by-step approach allows for a comprehensive understanding of the code's functionality, leading to accurate inferences, relevant examples, and the identification of potential pitfalls. The key is to move from a high-level understanding to a more detailed examination of the code's structure and logic.
这段代码是 Go 语言编译器中用于构建**控制流图 (Control Flow Graph, CFG)** 的一部分。它定义了一个 `builder` 结构体和一系列方法，用于将 Go 语言的抽象语法树 (AST) 转换为 CFG。

**主要功能:**

1. **遍历 AST 节点:**  `builder` 结构体的方法，特别是 `stmt` 函数，负责递归地遍历 Go 语言代码的抽象语法树 (AST)。
2. **创建基本块 (Basic Blocks):**  每当遇到不同的控制流结构（如顺序执行、条件分支、循环等）时，`builder` 会创建新的 `Block` 结构体来表示 CFG 中的基本块。基本块是一段没有内部控制流转移的顺序执行的代码。
3. **连接基本块 (构建控制流边):**  `builder` 的方法会根据 Go 语言的控制流语义，在不同的基本块之间添加控制流边。例如，`if` 语句会产生到 `then` 分支和 `else` 分支的边。
4. **处理控制流语句:**  `builder` 专门处理像 `if`, `for`, `switch`, `select`, `return`, `break`, `continue`, `goto` 等控制流语句，确保 CFG 正确反映程序的执行流程。
5. **处理标签 (Labels):** `builder` 维护一个 `lblocks` 映射来跟踪代码中的标签，并为带有标签的语句创建对应的基本块，用于支持 `goto`, `break` 和 `continue` 语句。
6. **处理 `break`, `continue` 和 `fallthrough`:**  `targets` 结构体和相关逻辑用于跟踪循环和 `switch` 语句的 `break` 和 `continue` 目标，以及 `switch` 语句的 `fallthrough` 行为。
7. **处理 `defer` 和 `go` 语句:** 虽然代码中没有显式地对 `defer` 和 `go` 语句进行特殊的 CFG 构造，但它们会被添加到当前基本块的 `Nodes` 中，在后续的分析中可能会被特殊处理。
8. **处理不可达代码:**  对于像 `panic` 或 `os.Exit` 这样的不会返回的函数调用，`builder` 会创建一个 `KindUnreachable` 类型的基本块，表示程序执行到这里后不会继续向下执行。

**它可以被推理为实现 Go 语言的控制流图 (CFG) 构建功能。**

**Go 代码示例:**

假设我们有以下简单的 Go 代码：

```go
package main

func main() {
	x := 10
	if x > 5 {
		println("x is greater than 5")
	} else {
		println("x is not greater than 5")
	}
	println("done")
}
```

**假设输入 (AST 结构简化):**

```
// ... 一系列代表上述 Go 代码的 AST 节点 ...
// 例如：
// *ast.FuncDecl (main 函数声明)
//   *ast.BlockStmt (函数体)
//     *ast.AssignStmt (x := 10)
//     *ast.IfStmt (if x > 5 ...)
//       *ast.BinaryExpr (x > 5)
//       *ast.BlockStmt (then 分支)
//         *ast.ExprStmt (println(...))
//       *ast.BlockStmt (else 分支)
//         *ast.ExprStmt (println(...))
//     *ast.ExprStmt (println("done"))
```

**代码推理和输出 (CFG 结构简化):**

`builder` 会根据 AST 逐步构建 CFG，大致过程如下：

1. **创建起始块:** 为 `main` 函数创建一个起始基本块。
2. **处理 `x := 10`:** 将赋值语句添加到当前基本块。
3. **处理 `if x > 5`:**
   - 创建一个条件判断基本块（`KindIfThen`）。
   - 创建 `then` 分支的基本块（`KindIfThen`）。
   - 创建 `else` 分支的基本块（`KindIfElse`）。
   - 创建 `if` 语句结束后的基本块（`KindIfDone`）。
   - 添加从当前基本块到条件判断块的边。
   - 添加从条件判断块到 `then` 分支和 `else` 分支的边。
4. **处理 `then` 分支中的 `println`:** 将 `println` 语句添加到 `then` 分支的基本块，并添加从 `then` 分支到 `KindIfDone` 块的边。
5. **处理 `else` 分支中的 `println`:** 将 `println` 语句添加到 `else` 分支的基本块，并添加从 `else` 分支到 `KindIfDone` 块的边。
6. **处理 `println("done")`:** 将 `println` 语句添加到 `KindIfDone` 基本块。

**预期的 CFG (简化表示):**

```
Block 0 (KindStart):  // 函数入口
  Nodes: []
  Succs: [Block 1]

Block 1 (KindPlain):  // x := 10
  Nodes: [*ast.AssignStmt]
  Succs: [Block 2]

Block 2 (KindIfThen): // if x > 5
  Nodes: [*ast.BinaryExpr]
  Succs: [Block 3, Block 4] // 指向 then 和 else 分支

Block 3 (KindIfThen): // println("x is greater than 5")
  Nodes: [*ast.ExprStmt]
  Succs: [Block 5]

Block 4 (KindIfElse): // println("x is not greater than 5")
  Nodes: [*ast.ExprStmt]
  Succs: [Block 5]

Block 5 (KindIfDone): // println("done")
  Nodes: [*ast.ExprStmt]
  Succs: [] // 函数结束
```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。它是 `go/analysis` 工具链的一部分，通常会被其他工具调用，例如 `go vet` 或自定义的静态分析工具。这些上层工具会负责解析命令行参数，并将必要的信息传递给 CFG 构建过程。

例如，如果一个静态分析工具需要构建某个特定包的 CFG，它会使用 Go 的 `go/packages` 库加载包的信息，包括 AST，然后将 AST 传递给 `cfg.New` 或类似的函数，该函数会创建 `builder` 实例并开始构建 CFG。

**使用者易犯错的点:**

对于直接使用 `cfg` 包构建 CFG 的使用者来说，可能会犯以下错误：

1. **错误地理解基本块的概念:**  可能会将包含控制流转移的语句放在同一个基本块中，导致 CFG 不准确。
2. **没有正确处理所有控制流语句:**  例如，忘记处理 `select` 语句的各种情况，或者对 `defer` 和 `go` 语句的处理不当。
3. **在构建 CFG 之后修改 AST:**  CFG 是基于构建时的 AST 状态生成的，如果在 CFG 构建完成后修改了 AST，CFG 可能会变得无效。
4. **没有处理标签的可见性:**  在复杂的控制流中，标签的作用域可能会引起混淆，导致 `break` 或 `continue` 语句的目标不明确。

**示例 (易犯错的 `switch` 语句):**

考虑以下 `switch` 语句：

```go
switch i {
case 1:
	println("one")
case 2:
	println("two")
	// 忘记 break，会 fallthrough
case 3:
	println("three")
}
```

如果构建 CFG 的过程没有正确处理 `fallthrough` 的情况（虽然这段代码中已经考虑了 `fallthrough`），可能会错误地将 `case 2` 和 `case 3` 的代码放在不同的基本块中，并且没有添加从 `case 2` 到 `case 3` 的 `fallthrough` 边。正确的 CFG 会包含这条边，表示当 `i == 2` 时，程序会先执行 `println("two")`，然后继续执行 `println("three")`。

这段代码的作者已经考虑了 `fallthrough` 的情况，通过 `b.targets` 栈来维护 `fallthrough` 的目标。但是，如果使用者在构建 CFG *之后*，假设 CFG 已经被构建好了，并且基于这个 CFG 进行分析，可能会因为没有意识到 `case 2` 会 `fallthrough` 到 `case 3` 而导致分析结果错误。

总而言之，这段 `builder.go` 代码是 Go 语言编译器中一个核心的组件，负责将 Go 源代码的结构化表示（AST）转换为更适合进行控制流分析的图结构（CFG）。理解其功能对于进行静态分析、代码优化等底层工具开发至关重要。

Prompt: 
```
这是路径为go/src/cmd/vendor/golang.org/x/tools/go/cfg/builder.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cfg

// This file implements the CFG construction pass.

import (
	"fmt"
	"go/ast"
	"go/token"
)

type builder struct {
	cfg       *CFG
	mayReturn func(*ast.CallExpr) bool
	current   *Block
	lblocks   map[string]*lblock // labeled blocks
	targets   *targets           // linked stack of branch targets
}

func (b *builder) stmt(_s ast.Stmt) {
	// The label of the current statement.  If non-nil, its _goto
	// target is always set; its _break and _continue are set only
	// within the body of switch/typeswitch/select/for/range.
	// It is effectively an additional default-nil parameter of stmt().
	var label *lblock
start:
	switch s := _s.(type) {
	case *ast.BadStmt,
		*ast.SendStmt,
		*ast.IncDecStmt,
		*ast.GoStmt,
		*ast.DeferStmt,
		*ast.EmptyStmt,
		*ast.AssignStmt:
		// No effect on control flow.
		b.add(s)

	case *ast.ExprStmt:
		b.add(s)
		if call, ok := s.X.(*ast.CallExpr); ok && !b.mayReturn(call) {
			// Calls to panic, os.Exit, etc, never return.
			b.current = b.newBlock(KindUnreachable, s)
		}

	case *ast.DeclStmt:
		// Treat each var ValueSpec as a separate statement.
		d := s.Decl.(*ast.GenDecl)
		if d.Tok == token.VAR {
			for _, spec := range d.Specs {
				if spec, ok := spec.(*ast.ValueSpec); ok {
					b.add(spec)
				}
			}
		}

	case *ast.LabeledStmt:
		label = b.labeledBlock(s.Label, s)
		b.jump(label._goto)
		b.current = label._goto
		_s = s.Stmt
		goto start // effectively: tailcall stmt(g, s.Stmt, label)

	case *ast.ReturnStmt:
		b.add(s)
		b.current = b.newBlock(KindUnreachable, s)

	case *ast.BranchStmt:
		b.branchStmt(s)

	case *ast.BlockStmt:
		b.stmtList(s.List)

	case *ast.IfStmt:
		if s.Init != nil {
			b.stmt(s.Init)
		}
		then := b.newBlock(KindIfThen, s)
		done := b.newBlock(KindIfDone, s)
		_else := done
		if s.Else != nil {
			_else = b.newBlock(KindIfElse, s)
		}
		b.add(s.Cond)
		b.ifelse(then, _else)
		b.current = then
		b.stmt(s.Body)
		b.jump(done)

		if s.Else != nil {
			b.current = _else
			b.stmt(s.Else)
			b.jump(done)
		}

		b.current = done

	case *ast.SwitchStmt:
		b.switchStmt(s, label)

	case *ast.TypeSwitchStmt:
		b.typeSwitchStmt(s, label)

	case *ast.SelectStmt:
		b.selectStmt(s, label)

	case *ast.ForStmt:
		b.forStmt(s, label)

	case *ast.RangeStmt:
		b.rangeStmt(s, label)

	default:
		panic(fmt.Sprintf("unexpected statement kind: %T", s))
	}
}

func (b *builder) stmtList(list []ast.Stmt) {
	for _, s := range list {
		b.stmt(s)
	}
}

func (b *builder) branchStmt(s *ast.BranchStmt) {
	var block *Block
	switch s.Tok {
	case token.BREAK:
		if s.Label != nil {
			if lb := b.labeledBlock(s.Label, nil); lb != nil {
				block = lb._break
			}
		} else {
			for t := b.targets; t != nil && block == nil; t = t.tail {
				block = t._break
			}
		}

	case token.CONTINUE:
		if s.Label != nil {
			if lb := b.labeledBlock(s.Label, nil); lb != nil {
				block = lb._continue
			}
		} else {
			for t := b.targets; t != nil && block == nil; t = t.tail {
				block = t._continue
			}
		}

	case token.FALLTHROUGH:
		for t := b.targets; t != nil && block == nil; t = t.tail {
			block = t._fallthrough
		}

	case token.GOTO:
		if s.Label != nil {
			block = b.labeledBlock(s.Label, nil)._goto
		}
	}
	if block == nil { // ill-typed (e.g. undefined label)
		block = b.newBlock(KindUnreachable, s)
	}
	b.jump(block)
	b.current = b.newBlock(KindUnreachable, s)
}

func (b *builder) switchStmt(s *ast.SwitchStmt, label *lblock) {
	if s.Init != nil {
		b.stmt(s.Init)
	}
	if s.Tag != nil {
		b.add(s.Tag)
	}
	done := b.newBlock(KindSwitchDone, s)
	if label != nil {
		label._break = done
	}
	// We pull the default case (if present) down to the end.
	// But each fallthrough label must point to the next
	// body block in source order, so we preallocate a
	// body block (fallthru) for the next case.
	// Unfortunately this makes for a confusing block order.
	var defaultBody *[]ast.Stmt
	var defaultFallthrough *Block
	var fallthru, defaultBlock *Block
	ncases := len(s.Body.List)
	for i, clause := range s.Body.List {
		body := fallthru
		if body == nil {
			body = b.newBlock(KindSwitchCaseBody, clause) // first case only
		}

		// Preallocate body block for the next case.
		fallthru = done
		if i+1 < ncases {
			fallthru = b.newBlock(KindSwitchCaseBody, s.Body.List[i+1])
		}

		cc := clause.(*ast.CaseClause)
		if cc.List == nil {
			// Default case.
			defaultBody = &cc.Body
			defaultFallthrough = fallthru
			defaultBlock = body
			continue
		}

		var nextCond *Block
		for _, cond := range cc.List {
			nextCond = b.newBlock(KindSwitchNextCase, cc)
			b.add(cond) // one half of the tag==cond condition
			b.ifelse(body, nextCond)
			b.current = nextCond
		}
		b.current = body
		b.targets = &targets{
			tail:         b.targets,
			_break:       done,
			_fallthrough: fallthru,
		}
		b.stmtList(cc.Body)
		b.targets = b.targets.tail
		b.jump(done)
		b.current = nextCond
	}
	if defaultBlock != nil {
		b.jump(defaultBlock)
		b.current = defaultBlock
		b.targets = &targets{
			tail:         b.targets,
			_break:       done,
			_fallthrough: defaultFallthrough,
		}
		b.stmtList(*defaultBody)
		b.targets = b.targets.tail
	}
	b.jump(done)
	b.current = done
}

func (b *builder) typeSwitchStmt(s *ast.TypeSwitchStmt, label *lblock) {
	if s.Init != nil {
		b.stmt(s.Init)
	}
	if s.Assign != nil {
		b.add(s.Assign)
	}

	done := b.newBlock(KindSwitchDone, s)
	if label != nil {
		label._break = done
	}
	var default_ *ast.CaseClause
	for _, clause := range s.Body.List {
		cc := clause.(*ast.CaseClause)
		if cc.List == nil {
			default_ = cc
			continue
		}
		body := b.newBlock(KindSwitchCaseBody, cc)
		var next *Block
		for _, casetype := range cc.List {
			next = b.newBlock(KindSwitchNextCase, cc)
			// casetype is a type, so don't call b.add(casetype).
			// This block logically contains a type assertion,
			// x.(casetype), but it's unclear how to represent x.
			_ = casetype
			b.ifelse(body, next)
			b.current = next
		}
		b.current = body
		b.typeCaseBody(cc, done)
		b.current = next
	}
	if default_ != nil {
		b.typeCaseBody(default_, done)
	} else {
		b.jump(done)
	}
	b.current = done
}

func (b *builder) typeCaseBody(cc *ast.CaseClause, done *Block) {
	b.targets = &targets{
		tail:   b.targets,
		_break: done,
	}
	b.stmtList(cc.Body)
	b.targets = b.targets.tail
	b.jump(done)
}

func (b *builder) selectStmt(s *ast.SelectStmt, label *lblock) {
	// First evaluate channel expressions.
	// TODO(adonovan): fix: evaluate only channel exprs here.
	for _, clause := range s.Body.List {
		if comm := clause.(*ast.CommClause).Comm; comm != nil {
			b.stmt(comm)
		}
	}

	done := b.newBlock(KindSelectDone, s)
	if label != nil {
		label._break = done
	}

	var defaultBody *[]ast.Stmt
	for _, cc := range s.Body.List {
		clause := cc.(*ast.CommClause)
		if clause.Comm == nil {
			defaultBody = &clause.Body
			continue
		}
		body := b.newBlock(KindSelectCaseBody, clause)
		next := b.newBlock(KindSelectAfterCase, clause)
		b.ifelse(body, next)
		b.current = body
		b.targets = &targets{
			tail:   b.targets,
			_break: done,
		}
		switch comm := clause.Comm.(type) {
		case *ast.ExprStmt: // <-ch
			// nop
		case *ast.AssignStmt: // x := <-states[state].Chan
			b.add(comm.Lhs[0])
		}
		b.stmtList(clause.Body)
		b.targets = b.targets.tail
		b.jump(done)
		b.current = next
	}
	if defaultBody != nil {
		b.targets = &targets{
			tail:   b.targets,
			_break: done,
		}
		b.stmtList(*defaultBody)
		b.targets = b.targets.tail
		b.jump(done)
	}
	b.current = done
}

func (b *builder) forStmt(s *ast.ForStmt, label *lblock) {
	//	...init...
	//      jump loop
	// loop:
	//      if cond goto body else done
	// body:
	//      ...body...
	//      jump post
	// post:				 (target of continue)
	//      ...post...
	//      jump loop
	// done:                                 (target of break)
	if s.Init != nil {
		b.stmt(s.Init)
	}
	body := b.newBlock(KindForBody, s)
	done := b.newBlock(KindForDone, s) // target of 'break'
	loop := body                       // target of back-edge
	if s.Cond != nil {
		loop = b.newBlock(KindForLoop, s)
	}
	cont := loop // target of 'continue'
	if s.Post != nil {
		cont = b.newBlock(KindForPost, s)
	}
	if label != nil {
		label._break = done
		label._continue = cont
	}
	b.jump(loop)
	b.current = loop
	if loop != body {
		b.add(s.Cond)
		b.ifelse(body, done)
		b.current = body
	}
	b.targets = &targets{
		tail:      b.targets,
		_break:    done,
		_continue: cont,
	}
	b.stmt(s.Body)
	b.targets = b.targets.tail
	b.jump(cont)

	if s.Post != nil {
		b.current = cont
		b.stmt(s.Post)
		b.jump(loop) // back-edge
	}
	b.current = done
}

func (b *builder) rangeStmt(s *ast.RangeStmt, label *lblock) {
	b.add(s.X)

	if s.Key != nil {
		b.add(s.Key)
	}
	if s.Value != nil {
		b.add(s.Value)
	}

	//      ...
	// loop:                                   (target of continue)
	// 	if ... goto body else done
	// body:
	//      ...
	// 	jump loop
	// done:                                   (target of break)

	loop := b.newBlock(KindRangeLoop, s)
	b.jump(loop)
	b.current = loop

	body := b.newBlock(KindRangeBody, s)
	done := b.newBlock(KindRangeDone, s)
	b.ifelse(body, done)
	b.current = body

	if label != nil {
		label._break = done
		label._continue = loop
	}
	b.targets = &targets{
		tail:      b.targets,
		_break:    done,
		_continue: loop,
	}
	b.stmt(s.Body)
	b.targets = b.targets.tail
	b.jump(loop) // back-edge
	b.current = done
}

// -------- helpers --------

// Destinations associated with unlabeled for/switch/select stmts.
// We push/pop one of these as we enter/leave each construct and for
// each BranchStmt we scan for the innermost target of the right type.
type targets struct {
	tail         *targets // rest of stack
	_break       *Block
	_continue    *Block
	_fallthrough *Block
}

// Destinations associated with a labeled block.
// We populate these as labels are encountered in forward gotos or
// labeled statements.
type lblock struct {
	_goto     *Block
	_break    *Block
	_continue *Block
}

// labeledBlock returns the branch target associated with the
// specified label, creating it if needed.
func (b *builder) labeledBlock(label *ast.Ident, stmt *ast.LabeledStmt) *lblock {
	lb := b.lblocks[label.Name]
	if lb == nil {
		lb = &lblock{_goto: b.newBlock(KindLabel, nil)}
		if b.lblocks == nil {
			b.lblocks = make(map[string]*lblock)
		}
		b.lblocks[label.Name] = lb
	}
	// Fill in the label later (in case of forward goto).
	// Stmt may be set already if labels are duplicated (ill-typed).
	if stmt != nil && lb._goto.Stmt == nil {
		lb._goto.Stmt = stmt
	}
	return lb
}

// newBlock appends a new unconnected basic block to b.cfg's block
// slice and returns it.
// It does not automatically become the current block.
// comment is an optional string for more readable debugging output.
func (b *builder) newBlock(kind BlockKind, stmt ast.Stmt) *Block {
	g := b.cfg
	block := &Block{
		Index: int32(len(g.Blocks)),
		Kind:  kind,
		Stmt:  stmt,
	}
	block.Succs = block.succs2[:0]
	g.Blocks = append(g.Blocks, block)
	return block
}

func (b *builder) add(n ast.Node) {
	b.current.Nodes = append(b.current.Nodes, n)
}

// jump adds an edge from the current block to the target block,
// and sets b.current to nil.
func (b *builder) jump(target *Block) {
	b.current.Succs = append(b.current.Succs, target)
	b.current = nil
}

// ifelse emits edges from the current block to the t and f blocks,
// and sets b.current to nil.
func (b *builder) ifelse(t, f *Block) {
	b.current.Succs = append(b.current.Succs, t, f)
	b.current = nil
}

"""



```