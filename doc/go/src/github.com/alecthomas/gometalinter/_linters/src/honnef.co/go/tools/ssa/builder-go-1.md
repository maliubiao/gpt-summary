Response:
Let's break down the thought process for analyzing this Go code snippet and fulfilling the request.

**1. Initial Understanding and Goal:**

The core task is to analyze a Go code snippet from `builder.go` and explain its functionality. The snippet appears to be part of a larger system for converting Go Abstract Syntax Trees (ASTs) into Static Single Assignment (SSA) form. The goal is to understand what Go language features this specific part handles.

**2. Identifying Key Code Blocks:**

The snippet contains several distinct functions within the `builder` struct:

* `compositeLit`: Handles composite literals (structs, arrays, slices, maps).
* `switchStmt`: Handles `switch` statements.
* `typeSwitchStmt`: Handles `type switch` statements.
* `selectStmt`: Handles `select` statements.
* `forStmt`: Handles `for` loops.
* `rangeStmt`: Handles `range` loops.

This immediately tells us the scope of the code: it's about control flow and data structure initialization in Go.

**3. Analyzing Each Function Individually:**

* **`compositeLit`:**  The code clearly branches based on the type of the composite literal. It handles structs (including implicit address-of), arrays/slices, and maps. The key action is creating SSA instructions like `MakeMap`, `Store`, etc. The comment about implicit `&` for pointer-to-struct literals in maps is a key insight.

* **`switchStmt`:** The comments mention treating `switch` like a chain of `if-else` statements. This suggests it's not optimizing for multi-way dispatch at this stage. The code iterates through cases, generates comparison instructions, and jumps to the appropriate body. The handling of `default` and `fallthrough` is important.

* **`typeSwitchStmt`:** The comments provide a detailed breakdown of how a `type switch` is lowered into a series of type assertions and conditional jumps. The example code in the comment is very helpful. It emphasizes the generation of `typeswitch,ok` operations.

* **`selectStmt`:** The code first evaluates the channels involved. It then generates a `Select` instruction and uses an `if-else` chain based on the selected case index. The handling of receive (with optional assignment and comma-ok) and send operations is crucial.

* **`forStmt`:**  The code structure for a standard `for` loop is quite straightforward: initialize, jump to the loop condition, check the condition, execute the body, execute the post-statement, jump back.

* **`rangeStmt`:** This function dispatches based on the type being ranged over (slice/array, channel, map/string). It calls helper functions (`rangeIndexed`, `rangeChan`, `rangeIter`) to handle the specifics of each range type. This suggests a pattern of breaking down complex logic into smaller, manageable pieces.

**4. Identifying the Overall Goal:**

Looking at the individual functions, the overarching goal becomes clear: to translate high-level Go constructs into a lower-level representation (SSA) that can be further analyzed or optimized. This involves:

* **Control Flow:** Transforming `switch`, `type switch`, `select`, `for`, and `range` into basic blocks and conditional jumps.
* **Data Structures:** Handling the creation and initialization of composite data structures.
* **Concurrency:**  Representing `go` and `defer` statements as SSA instructions.
* **Channel Operations:**  Translating send and receive operations.

**5. Generating Examples:**

For each Go feature, creating a simple, illustrative example is essential. The examples should demonstrate the input Go code and the *conceptual* output in SSA form (though we don't need to generate the exact SSA). The assumptions made during the translation (e.g., how `type switch` works) should be reflected in the examples.

**6. Considering Command-Line Arguments and Error Prone Areas:**

The code snippet itself doesn't directly handle command-line arguments. However, we know it's part of a larger system (gometalinter). Therefore, mentioning the potential for command-line arguments related to SSA generation or analysis in the broader context is relevant.

For error-prone areas, the key is to think about common mistakes developers make when using the Go features being handled:

* **`compositeLit`:**  Forgetting the `&` when initializing a pointer-to-struct in a map.
* **`switchStmt`:**  Misunderstanding `fallthrough`.
* **`typeSwitchStmt`:**  Not understanding the scope of the implicitly declared variable in each case.
* **`selectStmt`:**  Forgetting that a `select` blocks if no case is ready (and the behavior of `default`).
* **`rangeStmt`:**  Modifying the collection being ranged over.

**7. Structuring the Answer:**

Organize the answer logically, addressing each part of the prompt:

* **Functionality Listing:**  A bulleted list of the Go language features handled.
* **Go Language Feature Implementation (with examples):**  Describe each feature and provide a Go code example, along with a conceptual SSA translation, input, and output.
* **Command-Line Arguments:** Explain that the snippet doesn't directly handle them but point to the broader context.
* **Error-Prone Areas:** Provide specific examples of common mistakes.
* **Summary of Functionality:** A concise recap of the overall purpose.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Maybe focus on the specific SSA instructions generated.
* **Correction:**  The request asks for the *Go language features* implemented. Focusing on the Go syntax and the *effect* of the translation is more important than the low-level SSA details. The examples should illustrate the *behavior*, not just the SSA.
* **Initial thought:** Treat all control flow statements similarly.
* **Correction:**  Recognize that `type switch` and `select` have more complex lowering mechanisms than simple `if` or `for`. The comments in the code provide valuable clues here.
* **Initial thought:**  Only consider the code within the snippet.
* **Correction:** Acknowledge the broader context of the `builder` struct and the `gometalinter` project. This helps explain the purpose of the code.

By following this thought process, we can systematically analyze the code snippet and generate a comprehensive and accurate answer that addresses all parts of the request.
这是 `go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/builder.go` 文件的一部分，专门负责将 Go 语言的抽象语法树 (AST) 转换为静态单赋值形式 (SSA)。这是构建 SSA 中间表示的核心步骤，为后续的程序分析和优化提供基础。

**归纳其功能：**

这部分代码的主要功能是 **将 Go 语言的复合字面量、switch 语句 (包括类型 switch)、select 语句、for 循环 (包括 range 循环) 转换为 SSA 指令序列**。它负责理解这些高级 Go 语言结构的语义，并将其转化为更底层的、易于分析的 SSA 表示。

**具体功能列举：**

1. **处理复合字面量 (`compositeLit`)：**
    *   识别并处理不同类型的复合字面量，包括结构体、数组、切片和映射。
    *   为每种类型的字面量生成相应的 SSA 指令，例如创建映射 (`MakeMap`)、存储元素 (`Store`) 等。
    *   特别处理了映射字面量中键是复合字面量且映射键类型是指针的情况，会隐式地添加取地址操作 (`&`)。

2. **处理 switch 语句 (`switchStmt`)：**
    *   将 `switch` 语句转化为一系列的 `if-else` 链。
    *   为每个 `case` 子句生成比较指令，并根据比较结果跳转到相应的代码块。
    *   正确处理 `default` 子句和 `fallthrough` 语句。

3. **处理类型 switch 语句 (`typeSwitchStmt`)：**
    *   将 `type switch` 语句转化为一系列的类型断言和条件跳转。
    *   为每个 `case` 子句生成类型测试指令 (`typeswitch,ok`)，并根据测试结果跳转。
    *   处理 `case nil` 的情况。
    *   处理在 `type switch` 中隐式声明的变量。

4. **处理 select 语句 (`selectStmt`)：**
    *   评估所有 `case` 子句中的通道操作。
    *   生成 `Select` 指令，模拟 `select` 的行为，并返回被选中的 `case` 的索引。
    *   使用 `if-else` 链基于 `Select` 指令的结果分发到相应的 `case` 代码块。
    *   处理接收操作（包括赋值和可选的 `ok` 值）。
    *   处理发送操作。
    *   处理 `default` 子句。

5. **处理 for 循环 (`forStmt`)：**
    *   生成 `for` 循环的 SSA 基本块结构，包括循环头、循环体、循环后处理和循环结束块。
    *   处理循环的初始化、条件判断和后处理语句。
    *   支持 `break` 和 `continue` 语句。

6. **处理 range 循环 (`rangeStmt`)：**
    *   根据被迭代对象的类型（数组、切片、通道、映射、字符串）采取不同的处理方式。
    *   对于数组、切片，生成基于索引的循环 (`rangeIndexed`)。
    *   对于通道，生成接收操作的循环 (`rangeChan`)。
    *   对于映射和字符串，生成使用 `Range`/`Next`/`Extract` 指令的迭代循环 (`rangeIter`)。
    *   正确处理循环变量的定义和赋值。
    *   支持 `break` 和 `continue` 语句。

**Go 语言功能实现举例 (附带假设的输入与输出):**

**示例 1: 复合字面量 (结构体)**

```go
// 输入 Go 代码
type Point struct {
    X int
    Y int
}

func main() {
    p := Point{X: 10, Y: 20}
    println(p.X)
}
```

**假设的 SSA 输出 (简化表示):**

```
// ... 函数入口 ...
v1 = Alloc Point  // 分配 Point 类型的内存
v2 = Const 10     // 常量 10
v3 = FieldAddr v1, 0  // 获取 Point 的 X 字段的地址
Store v3, v2      // 将 10 存储到 v3 指向的内存

v4 = Const 20     // 常量 20
v5 = FieldAddr v1, 1  // 获取 Point 的 Y 字段的地址
Store v5, v4      // 将 20 存储到 v5 指向的内存

// ... 后续访问 p.X 的操作会加载 v3 的值 ...
```

**示例 2: switch 语句**

```go
// 输入 Go 代码
func main() {
    x := 2
    switch x {
    case 1:
        println("one")
    case 2:
        println("two")
    default:
        println("other")
    }
}
```

**假设的 SSA 输出 (简化表示):**

```
// ... 函数入口 ...
v1 = Const 2     // 常量 2
// switch x
goto switch.cond.1
switch.cond.1:
    v2 = Const 1     // 常量 1
    v3 = Eq v1, v2   // 比较 x == 1
    If v3 goto switch.body.1 else switch.cond.2
switch.body.1:
    // println("one") 的 SSA 指令
    goto switch.done
switch.cond.2:
    v4 = Const 2     // 常量 2
    v5 = Eq v1, v4   // 比较 x == 2
    If v5 goto switch.body.2 else switch.default
switch.body.2:
    // println("two") 的 SSA 指令
    goto switch.done
switch.default:
    // println("other") 的 SSA 指令
switch.done:
// ... 后续代码 ...
```

**命令行参数处理：**

这段代码本身不直接处理命令行参数。命令行参数的处理通常发生在 `gometalinter` 或其使用的 SSA 构建工具的入口点。这些参数可能会影响 SSA 构建的某些行为，例如是否启用某些优化或输出调试信息。

**使用者易犯错的点：**

这段代码是编译器内部的一部分，普通 Go 开发者不会直接使用它。但是，理解它的功能可以帮助开发者避免在使用相关 Go 语言特性时犯一些常见的错误：

*   **`switch` 语句中的 `fallthrough`：**  容易忘记 `fallthrough` 会无条件地执行下一个 `case` 的代码，即使下一个 `case` 的条件不满足。
*   **`type switch` 中变量的作用域：**  在每个 `case` 中隐式声明的变量只在该 `case` 的作用域内有效。
*   **`select` 语句的阻塞行为：**  如果 `select` 中没有 `default` 且所有 `case` 都无法执行，`select` 语句会一直阻塞，可能导致程序死锁。
*   **在 `range` 循环中修改被迭代的对象：**  在某些情况下（例如 range 切片），修改正在迭代的对象可能会导致未定义的行为。
*   **映射字面量中指针类型键的初始化：**  如果映射的键是指针类型，且使用复合字面量作为键，可能会忘记需要显式或隐式地取地址 (`&`)。

**总结：**

这段 `builder.go` 代码是 Go 语言编译器或相关分析工具的核心组件，负责将高级的 Go 语言结构转化为更底层的 SSA 表示。理解其功能有助于深入了解 Go 语言的编译过程和程序分析技术。它专注于处理控制流语句和数据结构的初始化，为后续的静态分析和优化奠定基础。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/ssa/builder.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
))
		}

	case *types.Map:
		m := &MakeMap{Reserve: intConst(int64(len(e.Elts)))}
		m.setPos(e.Lbrace)
		m.setType(typ)
		fn.emit(m)
		for _, e := range e.Elts {
			e := e.(*ast.KeyValueExpr)

			// If a key expression in a map literal is  itself a
			// composite literal, the type may be omitted.
			// For example:
			//	map[*struct{}]bool{{}: true}
			// An &-operation may be implied:
			//	map[*struct{}]bool{&struct{}{}: true}
			var key Value
			if _, ok := unparen(e.Key).(*ast.CompositeLit); ok && isPointer(t.Key()) {
				// A CompositeLit never evaluates to a pointer,
				// so if the type of the location is a pointer,
				// an &-operation is implied.
				key = b.addr(fn, e.Key, true).address(fn)
			} else {
				key = b.expr(fn, e.Key)
			}

			loc := element{
				m:   m,
				k:   emitConv(fn, key, t.Key()),
				t:   t.Elem(),
				pos: e.Colon,
			}

			// We call assign() only because it takes care
			// of any &-operation required in the recursive
			// case, e.g.,
			// map[int]*struct{}{0: {}} implies &struct{}{}.
			// In-place update is of course impossible,
			// and no storebuf is needed.
			b.assign(fn, &loc, e.Value, true, nil)
		}
		sb.store(&address{addr: addr, pos: e.Lbrace, expr: e}, m)

	default:
		panic("unexpected CompositeLit type: " + t.String())
	}
}

// switchStmt emits to fn code for the switch statement s, optionally
// labelled by label.
//
func (b *builder) switchStmt(fn *Function, s *ast.SwitchStmt, label *lblock) {
	// We treat SwitchStmt like a sequential if-else chain.
	// Multiway dispatch can be recovered later by ssautil.Switches()
	// to those cases that are free of side effects.
	if s.Init != nil {
		b.stmt(fn, s.Init)
	}
	var tag Value = vTrue
	if s.Tag != nil {
		tag = b.expr(fn, s.Tag)
	}
	done := fn.newBasicBlock("switch.done")
	if label != nil {
		label._break = done
	}
	// We pull the default case (if present) down to the end.
	// But each fallthrough label must point to the next
	// body block in source order, so we preallocate a
	// body block (fallthru) for the next case.
	// Unfortunately this makes for a confusing block order.
	var dfltBody *[]ast.Stmt
	var dfltFallthrough *BasicBlock
	var fallthru, dfltBlock *BasicBlock
	ncases := len(s.Body.List)
	for i, clause := range s.Body.List {
		body := fallthru
		if body == nil {
			body = fn.newBasicBlock("switch.body") // first case only
		}

		// Preallocate body block for the next case.
		fallthru = done
		if i+1 < ncases {
			fallthru = fn.newBasicBlock("switch.body")
		}

		cc := clause.(*ast.CaseClause)
		if cc.List == nil {
			// Default case.
			dfltBody = &cc.Body
			dfltFallthrough = fallthru
			dfltBlock = body
			continue
		}

		var nextCond *BasicBlock
		for _, cond := range cc.List {
			nextCond = fn.newBasicBlock("switch.next")
			// TODO(adonovan): opt: when tag==vTrue, we'd
			// get better code if we use b.cond(cond)
			// instead of BinOp(EQL, tag, b.expr(cond))
			// followed by If.  Don't forget conversions
			// though.
			cond := emitCompare(fn, token.EQL, tag, b.expr(fn, cond), cond.Pos())
			emitIf(fn, cond, body, nextCond)
			fn.currentBlock = nextCond
		}
		fn.currentBlock = body
		fn.targets = &targets{
			tail:         fn.targets,
			_break:       done,
			_fallthrough: fallthru,
		}
		b.stmtList(fn, cc.Body)
		fn.targets = fn.targets.tail
		emitJump(fn, done)
		fn.currentBlock = nextCond
	}
	if dfltBlock != nil {
		emitJump(fn, dfltBlock)
		fn.currentBlock = dfltBlock
		fn.targets = &targets{
			tail:         fn.targets,
			_break:       done,
			_fallthrough: dfltFallthrough,
		}
		b.stmtList(fn, *dfltBody)
		fn.targets = fn.targets.tail
	}
	emitJump(fn, done)
	fn.currentBlock = done
}

// typeSwitchStmt emits to fn code for the type switch statement s, optionally
// labelled by label.
//
func (b *builder) typeSwitchStmt(fn *Function, s *ast.TypeSwitchStmt, label *lblock) {
	// We treat TypeSwitchStmt like a sequential if-else chain.
	// Multiway dispatch can be recovered later by ssautil.Switches().

	// Typeswitch lowering:
	//
	// var x X
	// switch y := x.(type) {
	// case T1, T2: S1                  // >1 	(y := x)
	// case nil:    SN                  // nil 	(y := x)
	// default:     SD                  // 0 types 	(y := x)
	// case T3:     S3                  // 1 type 	(y := x.(T3))
	// }
	//
	//      ...s.Init...
	// 	x := eval x
	// .caseT1:
	// 	t1, ok1 := typeswitch,ok x <T1>
	// 	if ok1 then goto S1 else goto .caseT2
	// .caseT2:
	// 	t2, ok2 := typeswitch,ok x <T2>
	// 	if ok2 then goto S1 else goto .caseNil
	// .S1:
	//      y := x
	// 	...S1...
	// 	goto done
	// .caseNil:
	// 	if t2, ok2 := typeswitch,ok x <T2>
	// 	if x == nil then goto SN else goto .caseT3
	// .SN:
	//      y := x
	// 	...SN...
	// 	goto done
	// .caseT3:
	// 	t3, ok3 := typeswitch,ok x <T3>
	// 	if ok3 then goto S3 else goto default
	// .S3:
	//      y := t3
	// 	...S3...
	// 	goto done
	// .default:
	//      y := x
	// 	...SD...
	// 	goto done
	// .done:

	if s.Init != nil {
		b.stmt(fn, s.Init)
	}

	var x Value
	switch ass := s.Assign.(type) {
	case *ast.ExprStmt: // x.(type)
		x = b.expr(fn, unparen(ass.X).(*ast.TypeAssertExpr).X)
	case *ast.AssignStmt: // y := x.(type)
		x = b.expr(fn, unparen(ass.Rhs[0]).(*ast.TypeAssertExpr).X)
	}

	done := fn.newBasicBlock("typeswitch.done")
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
		body := fn.newBasicBlock("typeswitch.body")
		var next *BasicBlock
		var casetype types.Type
		var ti Value // ti, ok := typeassert,ok x <Ti>
		for _, cond := range cc.List {
			next = fn.newBasicBlock("typeswitch.next")
			casetype = fn.Pkg.typeOf(cond)
			var condv Value
			if casetype == tUntypedNil {
				condv = emitCompare(fn, token.EQL, x, nilConst(x.Type()), token.NoPos)
				ti = x
			} else {
				yok := emitTypeTest(fn, x, casetype, cc.Case)
				ti = emitExtract(fn, yok, 0)
				condv = emitExtract(fn, yok, 1)
			}
			emitIf(fn, condv, body, next)
			fn.currentBlock = next
		}
		if len(cc.List) != 1 {
			ti = x
		}
		fn.currentBlock = body
		b.typeCaseBody(fn, cc, ti, done)
		fn.currentBlock = next
	}
	if default_ != nil {
		b.typeCaseBody(fn, default_, x, done)
	} else {
		emitJump(fn, done)
	}
	fn.currentBlock = done
}

func (b *builder) typeCaseBody(fn *Function, cc *ast.CaseClause, x Value, done *BasicBlock) {
	if obj := fn.Pkg.info.Implicits[cc]; obj != nil {
		// In a switch y := x.(type), each case clause
		// implicitly declares a distinct object y.
		// In a single-type case, y has that type.
		// In multi-type cases, 'case nil' and default,
		// y has the same type as the interface operand.
		emitStore(fn, fn.addNamedLocal(obj), x, obj.Pos())
	}
	fn.targets = &targets{
		tail:   fn.targets,
		_break: done,
	}
	b.stmtList(fn, cc.Body)
	fn.targets = fn.targets.tail
	emitJump(fn, done)
}

// selectStmt emits to fn code for the select statement s, optionally
// labelled by label.
//
func (b *builder) selectStmt(fn *Function, s *ast.SelectStmt, label *lblock) {
	// A blocking select of a single case degenerates to a
	// simple send or receive.
	// TODO(adonovan): opt: is this optimization worth its weight?
	if len(s.Body.List) == 1 {
		clause := s.Body.List[0].(*ast.CommClause)
		if clause.Comm != nil {
			b.stmt(fn, clause.Comm)
			done := fn.newBasicBlock("select.done")
			if label != nil {
				label._break = done
			}
			fn.targets = &targets{
				tail:   fn.targets,
				_break: done,
			}
			b.stmtList(fn, clause.Body)
			fn.targets = fn.targets.tail
			emitJump(fn, done)
			fn.currentBlock = done
			return
		}
	}

	// First evaluate all channels in all cases, and find
	// the directions of each state.
	var states []*SelectState
	blocking := true
	debugInfo := fn.debugInfo()
	for _, clause := range s.Body.List {
		var st *SelectState
		switch comm := clause.(*ast.CommClause).Comm.(type) {
		case nil: // default case
			blocking = false
			continue

		case *ast.SendStmt: // ch<- i
			ch := b.expr(fn, comm.Chan)
			st = &SelectState{
				Dir:  types.SendOnly,
				Chan: ch,
				Send: emitConv(fn, b.expr(fn, comm.Value),
					ch.Type().Underlying().(*types.Chan).Elem()),
				Pos: comm.Arrow,
			}
			if debugInfo {
				st.DebugNode = comm
			}

		case *ast.AssignStmt: // x := <-ch
			recv := unparen(comm.Rhs[0]).(*ast.UnaryExpr)
			st = &SelectState{
				Dir:  types.RecvOnly,
				Chan: b.expr(fn, recv.X),
				Pos:  recv.OpPos,
			}
			if debugInfo {
				st.DebugNode = recv
			}

		case *ast.ExprStmt: // <-ch
			recv := unparen(comm.X).(*ast.UnaryExpr)
			st = &SelectState{
				Dir:  types.RecvOnly,
				Chan: b.expr(fn, recv.X),
				Pos:  recv.OpPos,
			}
			if debugInfo {
				st.DebugNode = recv
			}
		}
		states = append(states, st)
	}

	// We dispatch on the (fair) result of Select using a
	// sequential if-else chain, in effect:
	//
	// idx, recvOk, r0...r_n-1 := select(...)
	// if idx == 0 {  // receive on channel 0  (first receive => r0)
	//     x, ok := r0, recvOk
	//     ...state0...
	// } else if v == 1 {   // send on channel 1
	//     ...state1...
	// } else {
	//     ...default...
	// }
	sel := &Select{
		States:   states,
		Blocking: blocking,
	}
	sel.setPos(s.Select)
	var vars []*types.Var
	vars = append(vars, varIndex, varOk)
	for _, st := range states {
		if st.Dir == types.RecvOnly {
			tElem := st.Chan.Type().Underlying().(*types.Chan).Elem()
			vars = append(vars, anonVar(tElem))
		}
	}
	sel.setType(types.NewTuple(vars...))

	fn.emit(sel)
	idx := emitExtract(fn, sel, 0)

	done := fn.newBasicBlock("select.done")
	if label != nil {
		label._break = done
	}

	var defaultBody *[]ast.Stmt
	state := 0
	r := 2 // index in 'sel' tuple of value; increments if st.Dir==RECV
	for _, cc := range s.Body.List {
		clause := cc.(*ast.CommClause)
		if clause.Comm == nil {
			defaultBody = &clause.Body
			continue
		}
		body := fn.newBasicBlock("select.body")
		next := fn.newBasicBlock("select.next")
		emitIf(fn, emitCompare(fn, token.EQL, idx, intConst(int64(state)), token.NoPos), body, next)
		fn.currentBlock = body
		fn.targets = &targets{
			tail:   fn.targets,
			_break: done,
		}
		switch comm := clause.Comm.(type) {
		case *ast.ExprStmt: // <-ch
			if debugInfo {
				v := emitExtract(fn, sel, r)
				emitDebugRef(fn, states[state].DebugNode.(ast.Expr), v, false)
			}
			r++

		case *ast.AssignStmt: // x := <-states[state].Chan
			if comm.Tok == token.DEFINE {
				fn.addLocalForIdent(comm.Lhs[0].(*ast.Ident))
			}
			x := b.addr(fn, comm.Lhs[0], false) // non-escaping
			v := emitExtract(fn, sel, r)
			if debugInfo {
				emitDebugRef(fn, states[state].DebugNode.(ast.Expr), v, false)
			}
			x.store(fn, v)

			if len(comm.Lhs) == 2 { // x, ok := ...
				if comm.Tok == token.DEFINE {
					fn.addLocalForIdent(comm.Lhs[1].(*ast.Ident))
				}
				ok := b.addr(fn, comm.Lhs[1], false) // non-escaping
				ok.store(fn, emitExtract(fn, sel, 1))
			}
			r++
		}
		b.stmtList(fn, clause.Body)
		fn.targets = fn.targets.tail
		emitJump(fn, done)
		fn.currentBlock = next
		state++
	}
	if defaultBody != nil {
		fn.targets = &targets{
			tail:   fn.targets,
			_break: done,
		}
		b.stmtList(fn, *defaultBody)
		fn.targets = fn.targets.tail
	} else {
		// A blocking select must match some case.
		// (This should really be a runtime.errorString, not a string.)
		fn.emit(&Panic{
			X: emitConv(fn, stringConst("blocking select matched no case"), tEface),
		})
		fn.currentBlock = fn.newBasicBlock("unreachable")
	}
	emitJump(fn, done)
	fn.currentBlock = done
}

// forStmt emits to fn code for the for statement s, optionally
// labelled by label.
//
func (b *builder) forStmt(fn *Function, s *ast.ForStmt, label *lblock) {
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
		b.stmt(fn, s.Init)
	}
	body := fn.newBasicBlock("for.body")
	done := fn.newBasicBlock("for.done") // target of 'break'
	loop := body                         // target of back-edge
	if s.Cond != nil {
		loop = fn.newBasicBlock("for.loop")
	}
	cont := loop // target of 'continue'
	if s.Post != nil {
		cont = fn.newBasicBlock("for.post")
	}
	if label != nil {
		label._break = done
		label._continue = cont
	}
	emitJump(fn, loop)
	fn.currentBlock = loop
	if loop != body {
		b.cond(fn, s.Cond, body, done)
		fn.currentBlock = body
	}
	fn.targets = &targets{
		tail:      fn.targets,
		_break:    done,
		_continue: cont,
	}
	b.stmt(fn, s.Body)
	fn.targets = fn.targets.tail
	emitJump(fn, cont)

	if s.Post != nil {
		fn.currentBlock = cont
		b.stmt(fn, s.Post)
		emitJump(fn, loop) // back-edge
	}
	fn.currentBlock = done
}

// rangeIndexed emits to fn the header for an integer-indexed loop
// over array, *array or slice value x.
// The v result is defined only if tv is non-nil.
// forPos is the position of the "for" token.
//
func (b *builder) rangeIndexed(fn *Function, x Value, tv types.Type, pos token.Pos) (k, v Value, loop, done *BasicBlock) {
	//
	//      length = len(x)
	//      index = -1
	// loop:                                   (target of continue)
	//      index++
	// 	if index < length goto body else done
	// body:
	//      k = index
	//      v = x[index]
	//      ...body...
	// 	jump loop
	// done:                                   (target of break)

	// Determine number of iterations.
	var length Value
	if arr, ok := deref(x.Type()).Underlying().(*types.Array); ok {
		// For array or *array, the number of iterations is
		// known statically thanks to the type.  We avoid a
		// data dependence upon x, permitting later dead-code
		// elimination if x is pure, static unrolling, etc.
		// Ranging over a nil *array may have >0 iterations.
		// We still generate code for x, in case it has effects.
		length = intConst(arr.Len())
	} else {
		// length = len(x).
		var c Call
		c.Call.Value = makeLen(x.Type())
		c.Call.Args = []Value{x}
		c.setType(tInt)
		length = fn.emit(&c)
	}

	index := fn.addLocal(tInt, token.NoPos)
	emitStore(fn, index, intConst(-1), pos)

	loop = fn.newBasicBlock("rangeindex.loop")
	emitJump(fn, loop)
	fn.currentBlock = loop

	incr := &BinOp{
		Op: token.ADD,
		X:  emitLoad(fn, index),
		Y:  vOne,
	}
	incr.setType(tInt)
	emitStore(fn, index, fn.emit(incr), pos)

	body := fn.newBasicBlock("rangeindex.body")
	done = fn.newBasicBlock("rangeindex.done")
	emitIf(fn, emitCompare(fn, token.LSS, incr, length, token.NoPos), body, done)
	fn.currentBlock = body

	k = emitLoad(fn, index)
	if tv != nil {
		switch t := x.Type().Underlying().(type) {
		case *types.Array:
			instr := &Index{
				X:     x,
				Index: k,
			}
			instr.setType(t.Elem())
			v = fn.emit(instr)

		case *types.Pointer: // *array
			instr := &IndexAddr{
				X:     x,
				Index: k,
			}
			instr.setType(types.NewPointer(t.Elem().Underlying().(*types.Array).Elem()))
			v = emitLoad(fn, fn.emit(instr))

		case *types.Slice:
			instr := &IndexAddr{
				X:     x,
				Index: k,
			}
			instr.setType(types.NewPointer(t.Elem()))
			v = emitLoad(fn, fn.emit(instr))

		default:
			panic("rangeIndexed x:" + t.String())
		}
	}
	return
}

// rangeIter emits to fn the header for a loop using
// Range/Next/Extract to iterate over map or string value x.
// tk and tv are the types of the key/value results k and v, or nil
// if the respective component is not wanted.
//
func (b *builder) rangeIter(fn *Function, x Value, tk, tv types.Type, pos token.Pos) (k, v Value, loop, done *BasicBlock) {
	//
	//	it = range x
	// loop:                                   (target of continue)
	//	okv = next it                      (ok, key, value)
	//  	ok = extract okv #0
	// 	if ok goto body else done
	// body:
	// 	k = extract okv #1
	// 	v = extract okv #2
	//      ...body...
	// 	jump loop
	// done:                                   (target of break)
	//

	if tk == nil {
		tk = tInvalid
	}
	if tv == nil {
		tv = tInvalid
	}

	rng := &Range{X: x}
	rng.setPos(pos)
	rng.setType(tRangeIter)
	it := fn.emit(rng)

	loop = fn.newBasicBlock("rangeiter.loop")
	emitJump(fn, loop)
	fn.currentBlock = loop

	_, isString := x.Type().Underlying().(*types.Basic)

	okv := &Next{
		Iter:     it,
		IsString: isString,
	}
	okv.setType(types.NewTuple(
		varOk,
		newVar("k", tk),
		newVar("v", tv),
	))
	fn.emit(okv)

	body := fn.newBasicBlock("rangeiter.body")
	done = fn.newBasicBlock("rangeiter.done")
	emitIf(fn, emitExtract(fn, okv, 0), body, done)
	fn.currentBlock = body

	if tk != tInvalid {
		k = emitExtract(fn, okv, 1)
	}
	if tv != tInvalid {
		v = emitExtract(fn, okv, 2)
	}
	return
}

// rangeChan emits to fn the header for a loop that receives from
// channel x until it fails.
// tk is the channel's element type, or nil if the k result is
// not wanted
// pos is the position of the '=' or ':=' token.
//
func (b *builder) rangeChan(fn *Function, x Value, tk types.Type, pos token.Pos) (k Value, loop, done *BasicBlock) {
	//
	// loop:                                   (target of continue)
	//      ko = <-x                           (key, ok)
	//      ok = extract ko #1
	//      if ok goto body else done
	// body:
	//      k = extract ko #0
	//      ...
	//      goto loop
	// done:                                   (target of break)

	loop = fn.newBasicBlock("rangechan.loop")
	emitJump(fn, loop)
	fn.currentBlock = loop
	recv := &UnOp{
		Op:      token.ARROW,
		X:       x,
		CommaOk: true,
	}
	recv.setPos(pos)
	recv.setType(types.NewTuple(
		newVar("k", x.Type().Underlying().(*types.Chan).Elem()),
		varOk,
	))
	ko := fn.emit(recv)
	body := fn.newBasicBlock("rangechan.body")
	done = fn.newBasicBlock("rangechan.done")
	emitIf(fn, emitExtract(fn, ko, 1), body, done)
	fn.currentBlock = body
	if tk != nil {
		k = emitExtract(fn, ko, 0)
	}
	return
}

// rangeStmt emits to fn code for the range statement s, optionally
// labelled by label.
//
func (b *builder) rangeStmt(fn *Function, s *ast.RangeStmt, label *lblock) {
	var tk, tv types.Type
	if s.Key != nil && !isBlankIdent(s.Key) {
		tk = fn.Pkg.typeOf(s.Key)
	}
	if s.Value != nil && !isBlankIdent(s.Value) {
		tv = fn.Pkg.typeOf(s.Value)
	}

	// If iteration variables are defined (:=), this
	// occurs once outside the loop.
	//
	// Unlike a short variable declaration, a RangeStmt
	// using := never redeclares an existing variable; it
	// always creates a new one.
	if s.Tok == token.DEFINE {
		if tk != nil {
			fn.addLocalForIdent(s.Key.(*ast.Ident))
		}
		if tv != nil {
			fn.addLocalForIdent(s.Value.(*ast.Ident))
		}
	}

	x := b.expr(fn, s.X)

	var k, v Value
	var loop, done *BasicBlock
	switch rt := x.Type().Underlying().(type) {
	case *types.Slice, *types.Array, *types.Pointer: // *array
		k, v, loop, done = b.rangeIndexed(fn, x, tv, s.For)

	case *types.Chan:
		k, loop, done = b.rangeChan(fn, x, tk, s.For)

	case *types.Map, *types.Basic: // string
		k, v, loop, done = b.rangeIter(fn, x, tk, tv, s.For)

	default:
		panic("Cannot range over: " + rt.String())
	}

	// Evaluate both LHS expressions before we update either.
	var kl, vl lvalue
	if tk != nil {
		kl = b.addr(fn, s.Key, false) // non-escaping
	}
	if tv != nil {
		vl = b.addr(fn, s.Value, false) // non-escaping
	}
	if tk != nil {
		kl.store(fn, k)
	}
	if tv != nil {
		vl.store(fn, v)
	}

	if label != nil {
		label._break = done
		label._continue = loop
	}

	fn.targets = &targets{
		tail:      fn.targets,
		_break:    done,
		_continue: loop,
	}
	b.stmt(fn, s.Body)
	fn.targets = fn.targets.tail
	emitJump(fn, loop) // back-edge
	fn.currentBlock = done
}

// stmt lowers statement s to SSA form, emitting code to fn.
func (b *builder) stmt(fn *Function, _s ast.Stmt) {
	// The label of the current statement.  If non-nil, its _goto
	// target is always set; its _break and _continue are set only
	// within the body of switch/typeswitch/select/for/range.
	// It is effectively an additional default-nil parameter of stmt().
	var label *lblock
start:
	switch s := _s.(type) {
	case *ast.EmptyStmt:
		// ignore.  (Usually removed by gofmt.)

	case *ast.DeclStmt: // Con, Var or Typ
		d := s.Decl.(*ast.GenDecl)
		if d.Tok == token.VAR {
			for _, spec := range d.Specs {
				if vs, ok := spec.(*ast.ValueSpec); ok {
					b.localValueSpec(fn, vs)
				}
			}
		}

	case *ast.LabeledStmt:
		label = fn.labelledBlock(s.Label)
		emitJump(fn, label._goto)
		fn.currentBlock = label._goto
		_s = s.Stmt
		goto start // effectively: tailcall stmt(fn, s.Stmt, label)

	case *ast.ExprStmt:
		b.expr(fn, s.X)

	case *ast.SendStmt:
		fn.emit(&Send{
			Chan: b.expr(fn, s.Chan),
			X: emitConv(fn, b.expr(fn, s.Value),
				fn.Pkg.typeOf(s.Chan).Underlying().(*types.Chan).Elem()),
			pos: s.Arrow,
		})

	case *ast.IncDecStmt:
		op := token.ADD
		if s.Tok == token.DEC {
			op = token.SUB
		}
		loc := b.addr(fn, s.X, false)
		b.assignOp(fn, loc, NewConst(exact.MakeInt64(1), loc.typ()), op, s.Pos())

	case *ast.AssignStmt:
		switch s.Tok {
		case token.ASSIGN, token.DEFINE:
			b.assignStmt(fn, s.Lhs, s.Rhs, s.Tok == token.DEFINE)

		default: // +=, etc.
			op := s.Tok + token.ADD - token.ADD_ASSIGN
			b.assignOp(fn, b.addr(fn, s.Lhs[0], false), b.expr(fn, s.Rhs[0]), op, s.Pos())
		}

	case *ast.GoStmt:
		// The "intrinsics" new/make/len/cap are forbidden here.
		// panic is treated like an ordinary function call.
		v := Go{pos: s.Go}
		b.setCall(fn, s.Call, &v.Call)
		fn.emit(&v)

	case *ast.DeferStmt:
		// The "intrinsics" new/make/len/cap are forbidden here.
		// panic is treated like an ordinary function call.
		v := Defer{pos: s.Defer}
		b.setCall(fn, s.Call, &v.Call)
		fn.emit(&v)

		// A deferred call can cause recovery from panic,
		// and control resumes at the Recover block.
		createRecoverBlock(fn)

	case *ast.ReturnStmt:
		var results []Value
		if len(s.Results) == 1 && fn.Signature.Results().Len() > 1 {
			// Return of one expression in a multi-valued function.
			tuple := b.exprN(fn, s.Results[0])
			ttuple := tuple.Type().(*types.Tuple)
			for i, n := 0, ttuple.Len(); i < n; i++ {
				results = append(results,
					emitConv(fn, emitExtract(fn, tuple, i),
						fn.Signature.Results().At(i).Type()))
			}
		} else {
			// 1:1 return, or no-arg return in non-void function.
			for i, r := range s.Results {
				v := emitConv(fn, b.expr(fn, r), fn.Signature.Results().At(i).Type())
				results = append(results, v)
			}
		}
		if fn.namedResults != nil {
			// Function has named result parameters (NRPs).
			// Perform parallel assignment of return operands to NRPs.
			for i, r := range results {
				emitStore(fn, fn.namedResults[i], r, s.Return)
			}
		}
		// Run function calls deferred in this
		// function when explicitly returning from it.
		fn.emit(new(RunDefers))
		if fn.namedResults != nil {
			// Reload NRPs to form the result tuple.
			results = results[:0]
			for _, r := range fn.namedResults {
				results = append(results, emitLoad(fn, r))
			}
		}
		fn.emit(&Return{Results: results, pos: s.Return})
		fn.currentBlock = fn.newBasicBlock("unreachable")

	case *ast.BranchStmt:
		var block *BasicBlock
		switch s.Tok {
		case token.BREAK:
			if s.Label != nil {
				block = fn.labelledBlock(s.Label)._break
			} else {
				for t := fn.targets; t != nil && block == nil; t = t.tail {
					block = t._break
				}
			}

		case token.CONTINUE:
			if s.Label != nil {
				block = fn.labelledBlock(s.Label)._continue
			} else {
				for t := fn.targets; t != nil && block == nil; t = t.tail {
					block = t._continue
				}
			}

		case token.FALLTHROUGH:
			for t := fn.targets; t != nil && block == nil; t = t.tail {
				block = t._fallthrough
			}

		case token.GOTO:
			block = fn.labelledBlock(s.Label)._goto
		}
		emitJump(fn, block)
		fn.currentBlock = fn.newBasicBlock("unreachable")

	case *ast.BlockStmt:
		b.stmtList(fn, s.List)

	case *ast.IfStmt:
		if s.Init != nil {
			b.stmt(fn, s.Init)
		}
		then := fn.newBasicBlock("if.then")
		done := fn.newBasicBlock("if.done")
		els := done
		if s.Else != nil {
			els = fn.newBasicBlock("if.else")
		}
		b.cond(fn, s.Cond, then, els)
		fn.currentBlock = then
		b.stmt(fn, s.Body)
		emitJump(fn, done)

		if s.Else != nil {
			fn.currentBlock = els
			b.stmt(fn, s.Else)
			emitJump(fn, done)
		}

		fn.currentBlock = done

	case *ast.SwitchStmt:
		b.switchStmt(fn, s, label)

	case *ast.TypeSwitchStmt:
		b.typeSwitchStmt(fn, s, label)

	case *ast.SelectStmt:
		b.selectStmt(fn, s, label)

	case *ast.ForStmt:
		b.forStmt(fn, s, label)

	case *ast.RangeStmt:
		b.rangeStmt(fn, s, label)

	default:
		panic(fmt.Sprintf("unexpected statement kind: %T", s))
	}
}

// buildFunction builds SSA code for the body of function fn.  Idempotent.
func (b *builder) buildFunction(fn *Function) {
	if fn.Blocks != nil {
		return // building already started
	}

	var recvField *ast.FieldList
	var body *ast.BlockStmt
	var functype *ast.FuncType
	switch n := fn.syntax.(type) {
	case nil:
		return // not a Go source function.  (Synthetic, or from object file.)
	case *ast.FuncDecl:
		functype = n.Type
		recvField = n.Recv
		body = n.Body
	case *ast.FuncLit:
		functype = n.Type
		body = n.Body
	default:
		panic(n)
	}

	if body == nil {
		// External function.
		if fn.Params == nil {
			// This condition ensures we add a non-empty
			// params list once only, but we may attempt
			// the degenerate empty case repeatedly.
			// TODO(adonovan): opt: don't do that.

			// We set Function.Params even though there is no body
			// code to reference them.  This simplifies clients.
			if recv := fn.Signature.Recv(); recv != nil {
				fn.addParamObj(recv)
			}
			params := fn.Signature.Params()
			for i, n := 0, params.Len(); i < n; i++ {
				fn.addParamObj(params.At(i))
			}
		}
		return
	}
	if fn.Prog.mode&LogSource != 0 {
		defer logStack("build function %s @ %s", fn, fn.Prog.Fset.Position(fn.pos))()
	}
	fn.startBody()
	fn.createSyntacticParams(recvField, functype)
	b.stmt(fn, body)
	if cb := fn.currentBlock; cb != nil && (cb == fn.Blocks[0] || cb == fn.Recover || cb.Preds != nil) {
		// Control fell off the end of the function's body block.
		//
		// Block optimizations eliminate the current block, if
		// unreachable.  It is a builder invariant that
		// if this no-arg return is ill-typed for
		// fn.Signature.Results, this block must be
		// unreachable.  The sanity checker checks this.
		fn.emit(new(RunDefers))
		fn.emit(new(Return))
	}
	fn.finishBody()
}

// buildFuncDecl builds SSA code for the function or method declared
// by decl in package pkg.
//
func (b *builder) buildFuncDecl(pkg *Package, decl *ast.FuncDecl) {
	id := decl.Name
	if isBlankIdent(id) {
		return // discard
	}
	fn := pkg.values[pkg.info.Defs[id]].(*Function)
	if decl.Recv == nil && id.Name == "init" {
		var v Call
		v.Call.Value = fn
		v.setType(types.NewTuple())
		pkg.init.emit(&v)
	}
	b.buildFunction(fn)
}

// Build calls Package.Build for each package in prog.
// Building occurs in parallel unless the BuildSerially mode flag was set.
//
// Build is intended for whole-program analysis; a typical compiler
// need only build a single package.
//
// Build is idempotent and thread-safe.
//
func (prog *Program) Build() {
	var wg sync.WaitGroup
	for _, p := range prog.packages {
		if prog.mode&BuildSerially != 0 {
			p.Build()
		} else {
			wg.Add(1)
			go func(p *Package) {
				p.Build()
				wg.Done()
			}(p)
		}
	}
	wg.Wait()
}

// Build builds SSA code for all functions and vars in package p.
//
// Precondition: CreatePackage must have been called for all of p's
// direct imports (and hence its direct imports must have been
// error-free).
//
// Build is idempotent and thread-safe.
//
func (p *Package) Build() { p.buildOnce.Do(p.build) }

func (p *Package) build() {
	if p.info == nil {
		return // synthetic package, e.g. "testmain"
	}

	// Ensure we have runtime type info for all exported members.
	// TODO(adonovan): ideally belongs in memberFromObject, but
	// that would require package creation in topological order.
	for name, mem := range p.Members {
		if ast.IsExported(name) {
			p.Prog.needMethodsOf(mem.Type())
		}
	}
	if p.Prog.mode&LogSource != 0 {
		defer logStack("build %s", p)()
	}
	init := p.init
	init.startBody()

	var done *BasicBlock

	if p.Prog.mode&BareInits == 0 {
		// Make init() skip if package is already initialized.
		initguard := p.Var("init$guard")
		doinit := init.newBasicBlock("init.start")
		done = init.newBasicBlock("init.done")
		emitIf(init, emitLoad(init, initguard), done, doinit)
		init.currentBlock = doinit
		emitStore(init, initguard, vTrue, token.NoPos)

		// Call the init() function of each package we import.
		for _, pkg := range p.Pkg.Imports() {
			prereq := p.Prog.packages[pkg]
			if prereq == nil {
				panic(fmt.Sprintf("Package(%q).Build(): unsatisfied import: Program.CreatePackage(%q) was not called", p.Pkg.Path(), pkg.Path()))
			}
			var v Call
			v.Call.Value = prereq.init
			v.Call.pos = init.pos
			v.setType(types.NewTuple())
			init.emit(&v)
		}
	}

	var b builder

	// Initialize package-level vars in correct order.
	for _, varinit := range p.info.InitOrder {
		if init.Prog.mode&LogSource != 0 {
			fmt.Fprintf(os.Stderr, "build global initializer %v @ %s\n",
				varinit.Lhs, p.Prog.Fset.Position(varinit.Rhs.Pos()))
		}
		if len(varinit.Lhs) == 1 {
			// 1:1 initialization: var x, y = a(), b()
			var lval lvalue
			if v := varinit.Lhs[0]; v.Name() != "_" {
				lval = &address{addr: p.values[v].(*Global), pos: v.Pos()}
			} else {
				lval = blank{}
			}
			b.assign(init, lval, varinit.Rhs, true, nil)
		} else {
			// n:1 initialization: var x, y :=  f()
			tuple := b.exprN(init, varinit.Rhs)
			for i, v := range varinit.Lhs {
				if v.Name() == "_" {
					continue
				}
				emitStore(init, p.values[v].(*Global), emitExtract(init, tuple, i), v.Pos())
			}
		}
	}

	// Build all package-level functions, init functions
	// and methods, including unreachable/blank ones.
	// We build them in source order, but it's not significant.
	for _, file := range p.files {
		for _, decl := range file.Decls {
			if decl, ok := decl.(*ast.FuncDecl); ok {
				b.buildFuncDecl(p, decl)
			}
		}
	}

	// Finish up init().
	if p.Prog.mode&BareInits == 0 {
		emitJump(init, done)
		init.currentBlock = done
	}
	init.emit(new(Return))
	init.finishBody()

	p.info = nil // We no longer need ASTs or go/types deductions.

	if p.Prog.mode&SanityCheckFunctions != 0 {
		sanityCheckPackage(p)
	}
}

// Like ObjectOf, but panics instead of returning nil.
// Only valid during p's create and build phases.
func (p *Package) objectOf(id *ast.Ident) types.Object {
	if o := p.info.ObjectOf(id); o != nil {
		return o
	}
	panic(fmt.Sprintf("no types.Object for ast.Ident %s @ %s",
		id.Name, p.Prog.Fset.Position(id.Pos())))
}

// Like TypeOf, but panics instead of returning nil.
// Only valid during p's create and build phases.
func (p *Package) typeOf(e ast.Expr) types.Type {
	if T := p.info.TypeOf(e); T != nil {
		return T
	}
	panic(fmt.Sprintf("no type for %T @ %s",
		e, p.Prog.Fset.Position(e.Pos())))
}

"""




```