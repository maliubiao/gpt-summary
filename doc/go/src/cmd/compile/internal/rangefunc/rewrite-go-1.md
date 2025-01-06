Response:
The user wants a summary of the functionality of the provided Go code snippet, which is part of the `rewrite.go` file in the `go/src/cmd/compile/internal/rangefunc` package. This package seems to be responsible for rewriting range-over-function loops in Go.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name `rewrite.go` and the package `rangefunc` strongly suggest that this code is involved in modifying or transforming range-over-function loops.

2. **Analyze Key Functions:** Examine the functions present in the snippet to understand their individual roles.
    * `genBodyFunc`:  This function clearly constructs the body of a new function, likely the one executed in each iteration of the range loop. It handles parameter passing, assigning values, and potentially inserting checks for misuse.
    * `checks`: This function generates a series of conditional statements that are executed after each iteration of the loop. These checks seem related to handling `break`, `continue`, and `return` statements within the loop, and also potentially for detecting misuse of the range function.
    * Helper functions like `retStmt`, `ifNext`, `setValueType`, `assertReady`, `callPanic`, `next`, `forRangeFunc`, `intConst`, `stateConst`, `useObj`, `useList`, `makeVarName`, `generateParamName`, `declOuterVar`, `declSingleVar`, `runtimeSym`, and `setPos` support the core functionality.

3. **Infer the Overall Workflow:** Based on the functions, the likely workflow is:
    * Detect a range-over-function loop (`forRangeFunc`).
    * Generate a new function (`genBodyFunc`) that encapsulates the original loop body and manages the iteration logic.
    * Insert checks (`checks`) after each iteration to handle control flow and potential errors.
    * Replace the original range loop with a structure that calls the generated function.

4. **Focus on `genBodyFunc` Details:**  This function seems central. Observe its key steps:
    * Creates a new function.
    * Handles parameters: Reuses existing range variables or creates new ones, assigning them the values yielded by the range function.
    * Manages state (likely related to the progress of the iteration).
    * Appends the original loop body.
    * Adds logic for the end of the iteration (setting state and returning `true` to continue).
    * Includes error handling logic (`checkFuncMisuse`).

5. **Focus on `checks` Details:** This function is responsible for post-iteration actions. Note its responsibilities:
    * Handling `break` and `continue` statements within the loop.
    * Handling `return` statements within the loop.
    * Potentially checking for errors or misuse of the range function.
    * Logic seems to differentiate between nested loops.

6. **Consider the "Misuse" Checks:** The repeated calls to `r.checkFuncMisuse()` suggest a concern about how developers might incorrectly use range-over-function loops. The code inserts checks to detect these cases and potentially trigger panics.

7. **Connect to Go Language Features:** Range-over-function is a specific Go 1.22 feature. This code is directly implementing the compilation logic for this feature. The generated code aims to provide the correct semantics for iterating over values produced by a function.

8. **Structure the Summary:** Organize the findings into a coherent description of the code's functionality. Start with the high-level purpose and then delve into the details of the key functions.

9. **Refine and Clarify:** Ensure the language is clear and accurate. Avoid overly technical jargon where possible. Focus on the "what" and "why" of the code.

By following these steps, we can arrive at the summary provided in the initial good answer. The key is to understand the individual components and how they work together to achieve the overall goal of rewriting range-over-function loops.
这段代码是 `go/src/cmd/compile/internal/rangefunc/rewrite.go` 文件的一部分，它是 Go 编译器中用于处理 **range over function** 功能的代码。

**归纳一下它的功能：**

这段代码的主要功能是 **生成和插入用于 range-over-function 循环体执行的闭包函数，并添加必要的运行时检查和控制逻辑。**  它负责将一个 `for range f()` 这样的循环转换成更底层的 Go 代码，以便能够正确地迭代由函数 `f` 产生的值。

具体来说，这段代码片段做了以下几件事情：

1. **生成闭包函数 (`genBodyFunc`):**
   -  它为 range 循环的循环体创建一个新的匿名函数（闭包）。
   -  这个闭包函数的参数对应于 range 函数的返回值。
   -  它会将 range 函数的返回值赋值给循环变量。
   -  它会将原始的循环体代码添加到这个闭包函数中。
   -  它还会添加一些额外的逻辑，用于管理循环的状态和处理 `break`、`continue` 和 `return` 等语句。

2. **处理循环变量 (`genBodyFunc`):**
   -  如果 range 子句中定义了循环变量（例如 `for i, v := range f()`），代码会尝试重用这些变量作为闭包函数的参数。
   -  否则，它会声明新的参数，并将 range 函数的返回值赋值给这些参数，然后再将这些参数的值赋给循环变量。

3. **添加运行时状态检查 (`genBodyFunc`, `checks`):**
   -  为了处理 range-over-function 的一些特殊情况（例如在 range 函数内部调用 `panic`），代码会插入一些运行时状态检查。
   -  这些检查使用一个状态变量 (`#stateVarN`) 来跟踪循环的执行状态。
   -  例如，它会检查在循环体执行过程中是否发生了 `panic`。

4. **处理控制流语句 (`checks`):**
   -  `checks` 函数负责生成在每次循环迭代后执行的检查代码。
   -  这些检查用于处理 `break`、`continue` 和 `return` 等语句。
   -  它会根据循环的深度和执行状态来决定是否应该继续迭代，或者跳出循环。

**更详细的功能分解：**

- **`yClosures[bodyFunc] = true`:** 标记新生成的闭包函数为 "yield closure"，可能用于后续的优化或分析。
- **`setPos(bodyFunc, start)`:** 设置新生成函数的起始位置信息，用于错误报告等。
- **参数处理循环:**  这部分代码负责处理闭包函数的参数，以及如何将 range 函数的返回值赋值给循环变量。
- **`tv := syntax.TypeAndValue{...}` 和 `bodyFunc.SetTypeInfo(tv)`:** 设置新生成函数的类型信息。
- **`loop := r.forStack[len(r.forStack)-1]`:** 获取当前循环的信息。
- **`if r.checkFuncMisuse() { ... }`:** 这部分代码是为了检测开发者是否错误地使用了 range-over-function，例如在 range 函数内部不恰当地操作状态。如果检测到潜在的错误，会插入 `panicrangestate` 的调用。
- **`bodyFunc.Body.List = append(bodyFunc.Body.List, body...)`:** 将原始的循环体代码添加到闭包函数中。
- **`bodyFunc.Body.List = append(bodyFunc.Body.List, r.setState(abi.RF_READY, end))` 和 `ret := &syntax.ReturnStmt{Results: r.useObj(r.true)}`:** 在闭包函数的末尾，设置状态为 `RF_READY` 并返回 `true`，表示可以继续下一次迭代。
- **`checks(loop *forLoop, pos syntax.Pos) []syntax.Stmt`:** 这个函数生成在每次循环迭代后需要执行的检查语句，例如处理 `break` 和 `continue`。
- **`ifNext`:**  一个辅助函数，用于生成带有条件判断的 `if` 语句，通常用于检查 `#next` 变量的值。
- **`assertReady`:** 生成检查状态是否为 `RF_READY` 的 `if` 语句，如果不是则调用 `panicrangestate`。
- **`callPanic`:** 生成调用 `runtime.panicrangestate` 的语句。
- **`next`:** 返回对 `#next` 变量的引用，这个变量可能用于跟踪迭代器的状态。
- **`forRangeFunc`:** 检查一个 `syntax.Node` 是否是一个 range-over-function 循环。
- **`intConst` 和 `stateConst`:**  生成整型常量和状态常量的语法节点。
- **`useObj` 和 `useList`:** 生成对变量或变量列表的引用。
- **`makeVarName` 和 `generateParamName`:**  创建变量名和参数名。
- **`declOuterVar` 和 `declSingleVar`:** 声明变量。
- **`runtimePkg` 和 `runtimeSym`:**  模拟 `runtime` 包，用于引用 `runtime.panicrangestate` 等函数。
- **`setPos`:**  设置语法节点的起始位置信息。

**代码示例 (推断的 Go 代码结构):**

假设有以下 Go 代码：

```go
package main

import "fmt"

func generateNumbers() func() (int, bool) {
	count := 0
	return func() (int, bool) {
		if count < 3 {
			count++
			return count, true
		}
		return 0, false
	}
}

func main() {
	for num := range generateNumbers() {
		fmt.Println(num)
		if num >= 2 {
			break
		}
	}
}
```

编译器在处理 `for num := range generateNumbers()` 循环时，`rewrite.go` 中的代码（尤其是这段片段）会进行类似以下的转换（简化版，不完全等同）：

```go
package main

import "fmt"
import "runtime" // 假设引入了 runtime 包

func generateNumbers() func() (int, bool) {
	count := 0
	return func() (int, bool) {
		if count < 3 {
			count++
			return count, true
		}
		return 0, false
	}
}

func main() {
	// ... 一些初始化代码 ...
	rangeFunc := generateNumbers()

	bodyFunc := func() (ok bool) { // 生成的闭包函数
		p0, ok := rangeFunc() // 调用 range 函数
		if !ok {
			return false
		}
		num := p0 // 将返回值赋值给循环变量

		fmt.Println(num)
		if num >= 2 {
			// ... 处理 break 逻辑，可能涉及到状态变量的修改 ...
			return false // 停止迭代
		}
		return true // 继续迭代
	}

	for {
		if !bodyFunc() {
			break
		}
	}
}
```

**假设的输入与输出：**

**输入 (抽象语法树的一部分):** 代表 `for num := range generateNumbers() { ... }` 这个 range-over-function 循环的语法树节点。

**输出 (也是抽象语法树的一部分):**  代表转换后的代码结构，包括生成的闭包函数和循环控制逻辑。

**命令行参数:**

这段代码本身不直接处理命令行参数。它是 Go 编译器内部的一部分，Go 编译器的命令行参数会影响整个编译过程，但不会直接传递到这段特定的代码中。

**使用者易犯错的点:**

这段代码主要是编译器内部逻辑，普通 Go 开发者不会直接接触。但是，理解 range-over-function 的工作原理可以帮助避免一些常见的错误，例如：

- **在 range 函数内部不正确地管理状态:**  `checkFuncMisuse` 的存在表明，编译器会尝试检测一些不推荐的模式，比如在 range 函数返回后修改其内部状态。
- **对 range 函数的返回值做出不合理的假设:**  range 函数可以返回多个值和一个表示是否还有更多元素的布尔值。开发者需要正确处理这些返回值。

总而言之，这段代码是 Go 编译器实现 range-over-function 功能的关键部分，它负责生成执行循环体的闭包，并添加必要的运行时检查和控制逻辑，确保 range-over-function 能够按照预期工作。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/rangefunc/rewrite.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能

"""
yClosures[bodyFunc] = true
	setPos(bodyFunc, start)

	for i := 0; i < ftyp.Params().Len(); i++ {
		typ := ftyp.Params().At(i).Type()
		var paramVar *types2.Var
		if i < len(lhs) && def {
			// Reuse range variable as parameter.
			x := lhs[i]
			paramVar = r.info.Defs[x.(*syntax.Name)].(*types2.Var)
		} else {
			// Declare new parameter and assign it to range expression.
			paramVar = types2.NewVar(start, r.pkg, fmt.Sprintf("#p%d", 1+i), typ)
			if i < len(lhs) {
				x := lhs[i]
				as := &syntax.AssignStmt{Lhs: x, Rhs: r.useObj(paramVar)}
				as.SetPos(x.Pos())
				setPos(as.Rhs, x.Pos())
				bodyFunc.Body.List = append(bodyFunc.Body.List, as)
			}
		}
		params = append(params, paramVar)
	}

	tv := syntax.TypeAndValue{
		Type: types2.NewSignatureType(nil, nil, nil,
			types2.NewTuple(params...),
			types2.NewTuple(results...),
			false),
	}
	tv.SetIsValue()
	bodyFunc.SetTypeInfo(tv)

	loop := r.forStack[len(r.forStack)-1]

	if r.checkFuncMisuse() {
		// #tmpState := #stateVarN
		// #stateVarN = abi.RF_PANIC
		// if #tmpState != abi.RF_READY {
		//    runtime.panicrangestate(#tmpState)
		// }
		//
		// That is a slightly code-size-optimized version of
		//
		// if #stateVarN != abi.RF_READY {
		//	  #stateVarN = abi.RF_PANIC // If we ever need to specially detect "iterator swallowed checking panic" we put a different value here.
		//    runtime.panicrangestate(#tmpState)
		// }
		// #stateVarN = abi.RF_PANIC
		//

		tmpDecl, tmpState := r.declSingleVar("#tmpState", r.int.Type(), r.useObj(loop.stateVar))
		bodyFunc.Body.List = append(bodyFunc.Body.List, tmpDecl)
		bodyFunc.Body.List = append(bodyFunc.Body.List, r.setState(abi.RF_PANIC, start))
		bodyFunc.Body.List = append(bodyFunc.Body.List, r.assertReady(start, tmpState))
	}

	// Original loop body (already rewritten by editStmt during inspect).
	bodyFunc.Body.List = append(bodyFunc.Body.List, body...)

	// end of loop body, set state to abi.RF_READY and return true to continue iteration
	if r.checkFuncMisuse() {
		bodyFunc.Body.List = append(bodyFunc.Body.List, r.setState(abi.RF_READY, end))
	}
	ret := &syntax.ReturnStmt{Results: r.useObj(r.true)}
	ret.SetPos(end)
	bodyFunc.Body.List = append(bodyFunc.Body.List, ret)

	return bodyFunc
}

// checks returns the post-call checks that need to be done for the given loop.
func (r *rewriter) checks(loop *forLoop, pos syntax.Pos) []syntax.Stmt {
	var list []syntax.Stmt
	if len(loop.checkBranch) > 0 {
		did := make(map[branch]bool)
		for _, br := range loop.checkBranch {
			if did[br] {
				continue
			}
			did[br] = true
			doBranch := &syntax.BranchStmt{Tok: br.tok, Label: &syntax.Name{Value: br.label}}
			list = append(list, r.ifNext(syntax.Eql, r.branchNext[br], true, doBranch))
		}
	}

	curLoop := loop.depth - 1
	curLoopIndex := curLoop - 1

	if len(r.forStack) == 1 {
		if loop.checkRet {
			list = append(list, r.ifNext(syntax.Eql, -1, false, retStmt(nil)))
		}
	} else {

		// Idealized check, implemented more simply for now.

		//	// N == depth of this loop, one less than the one just exited.
		//	if #next != 0 {
		//		if #next >= perLoopStep*N-1 { // this loop
		//			if #next >= perLoopStep*N+1 { // error checking
		//      		runtime.panicrangestate(abi.RF_DONE)
		//   		}
		//			rv := #next & 1 == 1 // code generates into #next&1
		//			#next = 0
		//			return rv
		//		}
		// 		return false // or handle returns and gotos
		//	}

		if loop.checkRet {
			// Note: next < 0 also handles gotos handled by outer loops.
			// We set checkRet in that case to trigger this check.
			if r.checkFuncMisuse() {
				list = append(list, r.ifNext(syntax.Lss, 0, false, r.setStateAt(curLoopIndex, abi.RF_DONE), retStmt(r.useObj(r.false))))
			} else {
				list = append(list, r.ifNext(syntax.Lss, 0, false, retStmt(r.useObj(r.false))))
			}
		}

		depthStep := perLoopStep * (curLoop)

		if r.checkFuncMisuse() {
			list = append(list, r.ifNext(syntax.Gtr, depthStep, false, r.callPanic(pos, r.stateConst(abi.RF_DONE))))
		} else {
			list = append(list, r.ifNext(syntax.Gtr, depthStep, true))
		}

		if r.checkFuncMisuse() {
			if loop.checkContinue {
				list = append(list, r.ifNext(syntax.Eql, depthStep-1, true, r.setStateAt(curLoopIndex, abi.RF_READY), retStmt(r.useObj(r.true))))
			}

			if loop.checkBreak {
				list = append(list, r.ifNext(syntax.Eql, depthStep, true, r.setStateAt(curLoopIndex, abi.RF_DONE), retStmt(r.useObj(r.false))))
			}

			if loop.checkContinue || loop.checkBreak {
				list = append(list, r.ifNext(syntax.Gtr, 0, false, r.setStateAt(curLoopIndex, abi.RF_DONE), retStmt(r.useObj(r.false))))
			}

		} else {
			if loop.checkContinue {
				list = append(list, r.ifNext(syntax.Eql, depthStep-1, true, retStmt(r.useObj(r.true))))
			}
			if loop.checkBreak {
				list = append(list, r.ifNext(syntax.Eql, depthStep, true, retStmt(r.useObj(r.false))))
			}
			if loop.checkContinue || loop.checkBreak {
				list = append(list, r.ifNext(syntax.Gtr, 0, false, retStmt(r.useObj(r.false))))
			}
		}
	}

	for _, j := range list {
		setPos(j, pos)
	}
	return list
}

// retStmt returns a return statement returning the given return values.
func retStmt(results syntax.Expr) *syntax.ReturnStmt {
	return &syntax.ReturnStmt{Results: results}
}

// ifNext returns the statement:
//
//	if #next op c { [#next = 0;] thens... }
func (r *rewriter) ifNext(op syntax.Operator, c int, zeroNext bool, thens ...syntax.Stmt) syntax.Stmt {
	var thenList []syntax.Stmt
	if zeroNext {
		clr := &syntax.AssignStmt{
			Lhs: r.next(),
			Rhs: r.intConst(0),
		}
		thenList = append(thenList, clr)
	}
	for _, then := range thens {
		thenList = append(thenList, then)
	}
	nif := &syntax.IfStmt{
		Cond: r.cond(op, r.next(), r.intConst(c)),
		Then: &syntax.BlockStmt{
			List: thenList,
		},
	}
	return nif
}

// setValueType marks x as a value with type typ.
func setValueType(x syntax.Expr, typ syntax.Type) {
	tv := syntax.TypeAndValue{Type: typ}
	tv.SetIsValue()
	x.SetTypeInfo(tv)
}

// assertReady returns the statement:
//
//	if #tmpState != abi.RF_READY { runtime.panicrangestate(#tmpState) }
func (r *rewriter) assertReady(start syntax.Pos, tmpState *types2.Var) syntax.Stmt {

	nif := &syntax.IfStmt{
		Cond: r.cond(syntax.Neq, r.useObj(tmpState), r.stateConst(abi.RF_READY)),
		Then: &syntax.BlockStmt{
			List: []syntax.Stmt{
				r.callPanic(start, r.useObj(tmpState))},
		},
	}
	setPos(nif, start)
	return nif
}

func (r *rewriter) callPanic(start syntax.Pos, arg syntax.Expr) syntax.Stmt {
	callPanicExpr := &syntax.CallExpr{
		Fun:     runtimeSym(r.info, "panicrangestate"),
		ArgList: []syntax.Expr{arg},
	}
	setValueType(callPanicExpr, nil) // no result type
	return &syntax.ExprStmt{X: callPanicExpr}
}

// next returns a reference to the #next variable.
func (r *rewriter) next() *syntax.Name {
	if r.nextVar == nil {
		r.nextVar = r.declOuterVar("#next", r.int.Type(), nil)
	}
	return r.useObj(r.nextVar)
}

// forRangeFunc checks whether n is a range-over-func.
// If so, it returns n.(*syntax.ForStmt), true.
// Otherwise it returns nil, false.
func forRangeFunc(n syntax.Node) (*syntax.ForStmt, bool) {
	nfor, ok := n.(*syntax.ForStmt)
	if !ok {
		return nil, false
	}
	nrange, ok := nfor.Init.(*syntax.RangeClause)
	if !ok {
		return nil, false
	}
	_, ok = types2.CoreType(nrange.X.GetTypeInfo().Type).(*types2.Signature)
	if !ok {
		return nil, false
	}
	return nfor, true
}

// intConst returns syntax for an integer literal with the given value.
func (r *rewriter) intConst(c int) *syntax.BasicLit {
	lit := &syntax.BasicLit{
		Value: fmt.Sprint(c),
		Kind:  syntax.IntLit,
	}
	tv := syntax.TypeAndValue{Type: r.int.Type(), Value: constant.MakeInt64(int64(c))}
	tv.SetIsValue()
	lit.SetTypeInfo(tv)
	return lit
}

func (r *rewriter) stateConst(s abi.RF_State) *syntax.BasicLit {
	return r.intConst(int(s))
}

// useObj returns syntax for a reference to decl, which should be its declaration.
func (r *rewriter) useObj(obj types2.Object) *syntax.Name {
	n := syntax.NewName(nopos, obj.Name())
	tv := syntax.TypeAndValue{Type: obj.Type()}
	tv.SetIsValue()
	n.SetTypeInfo(tv)
	r.info.Uses[n] = obj
	return n
}

// useList is useVar for a list of decls.
func (r *rewriter) useList(vars []types2.Object) syntax.Expr {
	var new []syntax.Expr
	for _, obj := range vars {
		new = append(new, r.useObj(obj))
	}
	if len(new) == 1 {
		return new[0]
	}
	return &syntax.ListExpr{ElemList: new}
}

func (r *rewriter) makeVarName(pos syntax.Pos, name string, typ types2.Type) (*types2.Var, *syntax.Name) {
	obj := types2.NewVar(pos, r.pkg, name, typ)
	n := syntax.NewName(pos, name)
	tv := syntax.TypeAndValue{Type: typ}
	tv.SetIsValue()
	n.SetTypeInfo(tv)
	r.info.Defs[n] = obj
	return obj, n
}

func (r *rewriter) generateParamName(results []*syntax.Field, i int) {
	obj, n := r.sig.RenameResult(results, i)
	r.info.Defs[n] = obj
}

// declOuterVar declares a variable with a given name, type, and initializer value,
// in the same scope as the outermost loop in a loop nest.
func (r *rewriter) declOuterVar(name string, typ types2.Type, init syntax.Expr) *types2.Var {
	if r.declStmt == nil {
		r.declStmt = &syntax.DeclStmt{}
	}
	stmt := r.declStmt
	obj, n := r.makeVarName(stmt.Pos(), name, typ)
	stmt.DeclList = append(stmt.DeclList, &syntax.VarDecl{
		NameList: []*syntax.Name{n},
		// Note: Type is ignored
		Values: init,
	})
	return obj
}

// declSingleVar declares a variable with a given name, type, and initializer value,
// and returns both the declaration and variable, so that the declaration can be placed
// in a specific scope.
func (r *rewriter) declSingleVar(name string, typ types2.Type, init syntax.Expr) (*syntax.DeclStmt, *types2.Var) {
	stmt := &syntax.DeclStmt{}
	obj, n := r.makeVarName(stmt.Pos(), name, typ)
	stmt.DeclList = append(stmt.DeclList, &syntax.VarDecl{
		NameList: []*syntax.Name{n},
		// Note: Type is ignored
		Values: init,
	})
	return stmt, obj
}

// runtimePkg is a fake runtime package that contains what we need to refer to in package runtime.
var runtimePkg = func() *types2.Package {
	var nopos syntax.Pos
	pkg := types2.NewPackage("runtime", "runtime")
	anyType := types2.Universe.Lookup("any").Type()
	intType := types2.Universe.Lookup("int").Type()

	// func deferrangefunc() unsafe.Pointer
	obj := types2.NewFunc(nopos, pkg, "deferrangefunc", types2.NewSignatureType(nil, nil, nil, nil, types2.NewTuple(types2.NewParam(nopos, pkg, "extra", anyType)), false))
	pkg.Scope().Insert(obj)

	// func panicrangestate()
	obj = types2.NewFunc(nopos, pkg, "panicrangestate", types2.NewSignatureType(nil, nil, nil, types2.NewTuple(types2.NewParam(nopos, pkg, "state", intType)), nil, false))
	pkg.Scope().Insert(obj)

	return pkg
}()

// runtimeSym returns a reference to a symbol in the fake runtime package.
func runtimeSym(info *types2.Info, name string) *syntax.Name {
	obj := runtimePkg.Scope().Lookup(name)
	n := syntax.NewName(nopos, "runtime."+name)
	tv := syntax.TypeAndValue{Type: obj.Type()}
	tv.SetIsValue()
	tv.SetIsRuntimeHelper()
	n.SetTypeInfo(tv)
	info.Uses[n] = obj
	return n
}

// setPos walks the top structure of x that has no position assigned
// and assigns it all to have position pos.
// When setPos encounters a syntax node with a position assigned,
// setPos does not look inside that node.
// setPos only needs to handle syntax we create in this package;
// all other syntax should have positions assigned already.
func setPos(x syntax.Node, pos syntax.Pos) {
	if x == nil {
		return
	}
	syntax.Inspect(x, func(n syntax.Node) bool {
		if n == nil || n.Pos() != nopos {
			return false
		}
		n.SetPos(pos)
		switch n := n.(type) {
		case *syntax.BlockStmt:
			if n.Rbrace == nopos {
				n.Rbrace = pos
			}
		}
		return true
	})
}

"""




```