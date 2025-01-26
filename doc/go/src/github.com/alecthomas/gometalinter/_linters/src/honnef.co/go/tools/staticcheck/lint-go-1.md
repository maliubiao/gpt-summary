Response:
My thinking process to summarize the provided Go code snippet goes like this:

1. **Understand the Goal:** The request asks for a summary of the functionality of the provided Go code, which is identified as part of a static analysis tool (`staticcheck`). The request also specifies this is "part 2 of 3," implying there's a larger context.

2. **Identify Key Data Structures and Functions:** I scan the code for prominent types, methods, and loops. I see the `Checker` struct (implicitly through the receiver `c *Checker`), the `lint.Job` struct, and several methods on `Checker` like `CheckCanonicalHeaderKey`, `CheckBenchmarkN`, etc. The repeated `for _, ssafn := range j.Program.InitialFunctions` loop is a crucial pattern.

3. **Recognize the Core Pattern:** The structure of most of the `Check...` functions is similar:
    * Iterate through functions (`j.Program.InitialFunctions`).
    * Often iterate through blocks within functions (`ssafn.Blocks`).
    * Often iterate through instructions within blocks (`b.Instrs`).
    * Use `ast.Inspect` to traverse the abstract syntax tree (AST) of the code.
    * Perform specific checks based on the type of AST node or SSA instruction.
    * Report errors using `j.Errorf`.

4. **Categorize the Checks:**  As I read through the `Check...` functions, I start grouping them by the type of issue they're detecting. I see patterns related to:
    * **String comparisons:**  `CheckComparingString` (implicitly, from the code).
    * **HTTP header handling:** `CheckCanonicalHeaderKey`.
    * **Testing practices:** `CheckBenchmarkN`, `CheckConcurrentTesting`.
    * **Variable usage:** `CheckUnreadVariableValues`.
    * **Logic errors:** `CheckPredeterminedBooleanExprs`, `CheckNilMaps`, `CheckExtremeComparison`, `CheckLoopCondition`, `CheckIneffectiveLoop`, `CheckDoubleNegation`, `CheckRepeatedIfElse`, `CheckSillyBitwiseOps`.
    * **Resource management:** `CheckCyclicFinalizer`, `CheckLeakyTimeTick`, `CheckDeferLock`.
    * **Potential bugs:** `CheckSliceOutOfBounds`, `CheckNaNComparison`, `CheckInfiniteRecursion`, `CheckNilContext`, `CheckSeeker`, `CheckIneffectiveAppend`.
    * **Code style/best practices:** `CheckArgOverwritten`, `CheckNonOctalFileMode`, `CheckPureFunctions`, `CheckDeprecated`.
    * **Specific API usage:**  (The final snippet mentioning `io.Writer` and `bytes.Buffer` hints at this).

5. **Focus on the Provided Snippet:**  The request explicitly mentions this is part 2. I need to summarize *this specific* part. While the overall context is important, I must focus on the functions present in this code block.

6. **Synthesize the Summary:** I begin writing the summary by stating the main purpose: static analysis and identifying potential issues. Then, I list the specific checks implemented in this part, using the function names as a guide. I group similar checks together for better readability. I emphasize the core mechanisms: AST and SSA analysis.

7. **Review and Refine:** I reread the generated summary and compare it to the code. I ensure the summary is accurate and captures the key functionalities. I look for any redundancies or areas where I can be more concise. I double-check that I haven't included information from parts of the code that weren't provided. The final snippet relating to `io.Writer` and `bytes.Buffer` is incomplete, but I recognize it's likely a check for misuse of buffered writers. I decide to mention it in the summary, acknowledging its incomplete nature in the provided context.

By following these steps, I arrive at the provided summary, which accurately reflects the functionality of the given Go code snippet within the context of a static analysis tool. The categorization helps to organize the information, and focusing on the core mechanisms provides a higher-level understanding.
这段Go语言代码是 `staticcheck` 代码检查工具的一部分，专注于一系列静态代码分析检查。它的主要功能是**对Go语言代码进行深入的静态分析，以检测潜在的错误、不良实践和性能问题**。

更具体地说，这段代码实现了以下一系列独立的检查器（Checker），每个检查器都针对一种特定的代码模式或潜在问题：

**功能归纳:**

这段代码的核心功能是**实现了一系列独立的静态检查规则，用于检测Go代码中的特定模式，这些模式可能暗示错误、低效或不符合最佳实践。** 它通过分析代码的抽象语法树 (AST) 和静态单赋值形式 (SSA) 来实现这些检查。

**以下是各个检查器的功能总结：**

* **`CheckComparingString` (虽然代码中没有明确的函数名，但根据逻辑可以推断出这个功能):**  检测永远返回 `false` 的字符串相等性比较，当比较的两个字符串的长度区间没有交集时触发。
* **`CheckCanonicalHeaderKey`:** 检查 `net/http.Header` 的键是否已经规范化，如果不是，则发出警告。
* **`CheckBenchmarkN`:**  禁止在基准测试中直接赋值给 `b.N`，因为 `b.N` 的值由测试框架控制。
* **`CheckUnreadVariableValues`:** 检测已赋值但从未使用的变量值。
* **`CheckPredeterminedBooleanExprs`:**  检测总是返回相同布尔值的二元表达式，提示逻辑错误。
* **`CheckNilMaps`:**  检测向 `nil` map 进行赋值的操作，这会导致运行时 panic。
* **`CheckExtremeComparison`:** 检测与类型最大值或最小值进行的不必要的比较，这些比较的结果是预定的。
* **`CheckLoopCondition`:** 检测循环条件中使用的变量在循环体内永远不会被修改的情况，这会导致无限循环。
* **`CheckArgOverwritten`:** 检测函数参数在被使用之前就被覆盖的情况。
* **`CheckIneffectiveLoop`:** 检测循环体内的代码总是以相同的方式退出（例如，始终 `break` 或 `return`），使得循环执行多次变得没有意义。
* **`CheckNilContext`:**  建议不要传递 `nil` 的 `context.Context`，即使函数允许，而是使用 `context.TODO()`。
* **`CheckSeeker`:**  检测 `io.Seeker` 的 `Seek` 方法的第一个参数错误地使用了 `io.SeekStart` 等常量。
* **`CheckIneffectiveAppend`:** 检测 `append` 的结果没有被使用的情况，除非它被用于另一个 `append` 调用。
* **`CheckConcurrentTesting`:**  检测在并发执行的 goroutine 中调用了 `testing.T` 的某些方法（例如 `FailNow`），这些方法必须在测试的同一个 goroutine 中调用。
* **`CheckCyclicFinalizer`:**  检测 finalizer 闭包捕获了它所作用的对象，这会阻止垃圾回收器调用 finalizer。
* **`CheckSliceOutOfBounds`:**  基于值范围分析，检测可能导致切片越界访问的索引操作。
* **`CheckDeferLock`:** 检测在已经持有锁的情况下立即 `defer` 同一个锁的操作，这可能是想 `defer Unlock`。
* **`CheckNaNComparison`:** 检测与 `math.NaN()` 的比较，因为任何值都不等于 `NaN`，包括 `NaN` 本身。
* **`CheckInfiniteRecursion`:** 检测明显的无限递归调用。
* **`CheckLeakyTimeTick`:**  建议在非无限循环的函数中使用 `time.NewTicker` 而不是 `time.Tick`，以避免资源泄漏。
* **`CheckDoubleNegation`:** 检测对布尔值进行两次否定，这通常是冗余的。
* **`CheckRepeatedIfElse`:** 检测 `if-else if` 链中重复出现的条件。
* **`CheckSillyBitwiseOps`:** 检测与 0 进行的无意义的位运算（例如 `x & 0`, `x | 0`, `x ^ 0`）。
* **`CheckNonOctalFileMode`:**  检测文件模式参数使用了十进制数字字符串，提示可能期望的是八进制。
* **`CheckPureFunctions`:** 检测纯函数的返回值被忽略的情况，这可能表明代码存在逻辑错误。
* **`CheckDeprecated`:**  检测使用了已弃用的 API。
* **`callChecker` 和 `checkCalls`:**  提供了一种通用的机制来注册和执行基于特定调用模式的检查规则。
* **`CheckWriterBufferModified` (代码片段不完整):**  推测是检测 `io.Writer` 或 `bytes.Buffer` 等类型的参数在调用后被修改的情况，这可能违反了某些函数的约定。

**Go 代码示例说明:**

**1. `CheckCanonicalHeaderKey`:**

```go
package main

import (
	"fmt"
	"net/http"
)

func main() {
	headers := http.Header{}
	headers["content-type"] = []string{"application/json"} // 错误: "content-type" 应该为 "Content-Type"
	fmt.Println(headers)
}
```

**假设输入:**  上述 `main.go` 文件。

**输出:**  `staticcheck` 会报告一个错误，类似于： `"keys in http.Header are canonicalized, "content-type" is not canonical; fix the constant or use http.CanonicalHeaderKey"`。

**2. `CheckNilMaps`:**

```go
package main

func main() {
	var m map[string]int
	m["key"] = 1 // 错误: 向 nil map 赋值
}
```

**假设输入:**  上述 `main.go` 文件。

**输出:**  `staticcheck` 会报告一个错误，类似于： `"assignment to nil map"`。

**3. `CheckExtremeComparison`:**

```go
package main

import "math"

func main() {
	var x uint8 = 10
	if x > math.MaxUint8 { // 错误: uint8 的值永远不会大于 math.MaxUint8
		println("Impossible!")
	}
}
```

**假设输入:**  上述 `main.go` 文件。

**输出:**  `staticcheck` 会报告一个错误，类似于： `"no value of type uint8 is greater than math.MaxUint8"`。

**命令行参数处理:**

这段代码本身并没有直接处理命令行参数。它是一个代码检查器的实现。`staticcheck` 工具本身会处理命令行参数，例如指定要检查的目录或文件。

**使用者易犯错的点 (示例):**

* **在 `net/http.Header` 中使用非规范化的键:**  开发者可能会忘记 HTTP Header 的键是大小写敏感的，并且应该使用规范化的形式 (例如 "Content-Type" 而不是 "content-type")。`CheckCanonicalHeaderKey` 就是为了捕获这类错误。
* **向 `nil` map 赋值:**  初学者可能会忘记在使用 map 之前需要使用 `make` 进行初始化。`CheckNilMaps` 可以帮助发现这种潜在的运行时 panic。
* **不必要的比较:**  开发者可能无意中编写了永远为真或假的比较语句，这可能是逻辑错误。`CheckExtremeComparison` 和 `CheckPredeterminedBooleanExprs` 可以识别这些情况。

**总结:**

这段代码是 `staticcheck` 工具中一系列静态代码分析检查器的核心实现。它通过分析 Go 语言代码的 AST 和 SSA 表示，能够有效地检测多种潜在的错误和不良实践，帮助开发者提高代码质量和可靠性。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/staticcheck/lint.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共3部分，请归纳一下它的功能

"""
ge ssafn.Blocks {
			for _, ins := range b.Instrs {
				binop, ok := ins.(*ssa.BinOp)
				if !ok {
					continue
				}
				if binop.Op != token.EQL && binop.Op != token.NEQ {
					continue
				}
				_, ok1 := binop.X.(*ssa.Slice)
				_, ok2 := binop.Y.(*ssa.Slice)
				if !ok1 && !ok2 {
					continue
				}
				r := c.funcDescs.Get(ssafn).Ranges
				r1, ok1 := r.Get(binop.X).(vrp.StringInterval)
				r2, ok2 := r.Get(binop.Y).(vrp.StringInterval)
				if !ok1 || !ok2 {
					continue
				}
				if r1.Length.Intersection(r2.Length).Empty() {
					j.Errorf(binop, "comparing strings of different sizes for equality will always return false")
				}
			}
		}
	}
}

func (c *Checker) CheckCanonicalHeaderKey(j *lint.Job) {
	fn := func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if ok {
			// TODO(dh): This risks missing some Header reads, for
			// example in `h1["foo"] = h2["foo"]` – these edge
			// cases are probably rare enough to ignore for now.
			for _, expr := range assign.Lhs {
				op, ok := expr.(*ast.IndexExpr)
				if !ok {
					continue
				}
				if hasType(j, op.X, "net/http.Header") {
					return false
				}
			}
			return true
		}
		op, ok := node.(*ast.IndexExpr)
		if !ok {
			return true
		}
		if !hasType(j, op.X, "net/http.Header") {
			return true
		}
		s, ok := ExprToString(j, op.Index)
		if !ok {
			return true
		}
		if s == http.CanonicalHeaderKey(s) {
			return true
		}
		j.Errorf(op, "keys in http.Header are canonicalized, %q is not canonical; fix the constant or use http.CanonicalHeaderKey", s)
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckBenchmarkN(j *lint.Job) {
	fn := func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		sel, ok := assign.Lhs[0].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "N" {
			return true
		}
		if !hasType(j, sel.X, "*testing.B") {
			return true
		}
		j.Errorf(assign, "should not assign to %s", Render(j, sel))
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckUnreadVariableValues(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		if IsExample(ssafn) {
			continue
		}
		node := ssafn.Syntax()
		if node == nil {
			continue
		}

		ast.Inspect(node, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok {
				return true
			}
			if len(assign.Lhs) > 1 && len(assign.Rhs) == 1 {
				// Either a function call with multiple return values,
				// or a comma-ok assignment

				val, _ := ssafn.ValueForExpr(assign.Rhs[0])
				if val == nil {
					return true
				}
				refs := val.Referrers()
				if refs == nil {
					return true
				}
				for _, ref := range *refs {
					ex, ok := ref.(*ssa.Extract)
					if !ok {
						continue
					}
					exrefs := ex.Referrers()
					if exrefs == nil {
						continue
					}
					if len(FilterDebug(*exrefs)) == 0 {
						lhs := assign.Lhs[ex.Index]
						if ident, ok := lhs.(*ast.Ident); !ok || ok && ident.Name == "_" {
							continue
						}
						j.Errorf(lhs, "this value of %s is never used", lhs)
					}
				}
				return true
			}
			for i, lhs := range assign.Lhs {
				rhs := assign.Rhs[i]
				if ident, ok := lhs.(*ast.Ident); !ok || ok && ident.Name == "_" {
					continue
				}
				val, _ := ssafn.ValueForExpr(rhs)
				if val == nil {
					continue
				}

				refs := val.Referrers()
				if refs == nil {
					// TODO investigate why refs can be nil
					return true
				}
				if len(FilterDebug(*refs)) == 0 {
					j.Errorf(lhs, "this value of %s is never used", lhs)
				}
			}
			return true
		})
	}
}

func (c *Checker) CheckPredeterminedBooleanExprs(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		for _, block := range ssafn.Blocks {
			for _, ins := range block.Instrs {
				ssabinop, ok := ins.(*ssa.BinOp)
				if !ok {
					continue
				}
				switch ssabinop.Op {
				case token.GTR, token.LSS, token.EQL, token.NEQ, token.LEQ, token.GEQ:
				default:
					continue
				}

				xs, ok1 := consts(ssabinop.X, nil, nil)
				ys, ok2 := consts(ssabinop.Y, nil, nil)
				if !ok1 || !ok2 || len(xs) == 0 || len(ys) == 0 {
					continue
				}

				trues := 0
				for _, x := range xs {
					for _, y := range ys {
						if x.Value == nil {
							if y.Value == nil {
								trues++
							}
							continue
						}
						if constant.Compare(x.Value, ssabinop.Op, y.Value) {
							trues++
						}
					}
				}
				b := trues != 0
				if trues == 0 || trues == len(xs)*len(ys) {
					j.Errorf(ssabinop, "binary expression is always %t for all possible values (%s %s %s)",
						b, xs, ssabinop.Op, ys)
				}
			}
		}
	}
}

func (c *Checker) CheckNilMaps(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		for _, block := range ssafn.Blocks {
			for _, ins := range block.Instrs {
				mu, ok := ins.(*ssa.MapUpdate)
				if !ok {
					continue
				}
				c, ok := mu.Map.(*ssa.Const)
				if !ok {
					continue
				}
				if c.Value != nil {
					continue
				}
				j.Errorf(mu, "assignment to nil map")
			}
		}
	}
}

func (c *Checker) CheckExtremeComparison(j *lint.Job) {
	isobj := func(expr ast.Expr, name string) bool {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		return IsObject(ObjectOf(j, sel.Sel), name)
	}

	fn := func(node ast.Node) bool {
		expr, ok := node.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		tx := TypeOf(j, expr.X)
		basic, ok := tx.Underlying().(*types.Basic)
		if !ok {
			return true
		}

		var max string
		var min string

		switch basic.Kind() {
		case types.Uint8:
			max = "math.MaxUint8"
		case types.Uint16:
			max = "math.MaxUint16"
		case types.Uint32:
			max = "math.MaxUint32"
		case types.Uint64:
			max = "math.MaxUint64"
		case types.Uint:
			max = "math.MaxUint64"

		case types.Int8:
			min = "math.MinInt8"
			max = "math.MaxInt8"
		case types.Int16:
			min = "math.MinInt16"
			max = "math.MaxInt16"
		case types.Int32:
			min = "math.MinInt32"
			max = "math.MaxInt32"
		case types.Int64:
			min = "math.MinInt64"
			max = "math.MaxInt64"
		case types.Int:
			min = "math.MinInt64"
			max = "math.MaxInt64"
		}

		if (expr.Op == token.GTR || expr.Op == token.GEQ) && isobj(expr.Y, max) ||
			(expr.Op == token.LSS || expr.Op == token.LEQ) && isobj(expr.X, max) {
			j.Errorf(expr, "no value of type %s is greater than %s", basic, max)
		}
		if expr.Op == token.LEQ && isobj(expr.Y, max) ||
			expr.Op == token.GEQ && isobj(expr.X, max) {
			j.Errorf(expr, "every value of type %s is <= %s", basic, max)
		}

		if (basic.Info() & types.IsUnsigned) != 0 {
			if (expr.Op == token.LSS || expr.Op == token.LEQ) && IsIntLiteral(expr.Y, "0") ||
				(expr.Op == token.GTR || expr.Op == token.GEQ) && IsIntLiteral(expr.X, "0") {
				j.Errorf(expr, "no value of type %s is less than 0", basic)
			}
			if expr.Op == token.GEQ && IsIntLiteral(expr.Y, "0") ||
				expr.Op == token.LEQ && IsIntLiteral(expr.X, "0") {
				j.Errorf(expr, "every value of type %s is >= 0", basic)
			}
		} else {
			if (expr.Op == token.LSS || expr.Op == token.LEQ) && isobj(expr.Y, min) ||
				(expr.Op == token.GTR || expr.Op == token.GEQ) && isobj(expr.X, min) {
				j.Errorf(expr, "no value of type %s is less than %s", basic, min)
			}
			if expr.Op == token.GEQ && isobj(expr.Y, min) ||
				expr.Op == token.LEQ && isobj(expr.X, min) {
				j.Errorf(expr, "every value of type %s is >= %s", basic, min)
			}
		}

		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func consts(val ssa.Value, out []*ssa.Const, visitedPhis map[string]bool) ([]*ssa.Const, bool) {
	if visitedPhis == nil {
		visitedPhis = map[string]bool{}
	}
	var ok bool
	switch val := val.(type) {
	case *ssa.Phi:
		if visitedPhis[val.Name()] {
			break
		}
		visitedPhis[val.Name()] = true
		vals := val.Operands(nil)
		for _, phival := range vals {
			out, ok = consts(*phival, out, visitedPhis)
			if !ok {
				return nil, false
			}
		}
	case *ssa.Const:
		out = append(out, val)
	case *ssa.Convert:
		out, ok = consts(val.X, out, visitedPhis)
		if !ok {
			return nil, false
		}
	default:
		return nil, false
	}
	if len(out) < 2 {
		return out, true
	}
	uniq := []*ssa.Const{out[0]}
	for _, val := range out[1:] {
		if val.Value == uniq[len(uniq)-1].Value {
			continue
		}
		uniq = append(uniq, val)
	}
	return uniq, true
}

func (c *Checker) CheckLoopCondition(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		fn := func(node ast.Node) bool {
			loop, ok := node.(*ast.ForStmt)
			if !ok {
				return true
			}
			if loop.Init == nil || loop.Cond == nil || loop.Post == nil {
				return true
			}
			init, ok := loop.Init.(*ast.AssignStmt)
			if !ok || len(init.Lhs) != 1 || len(init.Rhs) != 1 {
				return true
			}
			cond, ok := loop.Cond.(*ast.BinaryExpr)
			if !ok {
				return true
			}
			x, ok := cond.X.(*ast.Ident)
			if !ok {
				return true
			}
			lhs, ok := init.Lhs[0].(*ast.Ident)
			if !ok {
				return true
			}
			if x.Obj != lhs.Obj {
				return true
			}
			if _, ok := loop.Post.(*ast.IncDecStmt); !ok {
				return true
			}

			v, isAddr := ssafn.ValueForExpr(cond.X)
			if v == nil || isAddr {
				return true
			}
			switch v := v.(type) {
			case *ssa.Phi:
				ops := v.Operands(nil)
				if len(ops) != 2 {
					return true
				}
				_, ok := (*ops[0]).(*ssa.Const)
				if !ok {
					return true
				}
				sigma, ok := (*ops[1]).(*ssa.Sigma)
				if !ok {
					return true
				}
				if sigma.X != v {
					return true
				}
			case *ssa.UnOp:
				return true
			}
			j.Errorf(cond, "variable in loop condition never changes")

			return true
		}
		Inspect(ssafn.Syntax(), fn)
	}
}

func (c *Checker) CheckArgOverwritten(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		fn := func(node ast.Node) bool {
			var typ *ast.FuncType
			var body *ast.BlockStmt
			switch fn := node.(type) {
			case *ast.FuncDecl:
				typ = fn.Type
				body = fn.Body
			case *ast.FuncLit:
				typ = fn.Type
				body = fn.Body
			}
			if body == nil {
				return true
			}
			if len(typ.Params.List) == 0 {
				return true
			}
			for _, field := range typ.Params.List {
				for _, arg := range field.Names {
					obj := ObjectOf(j, arg)
					var ssaobj *ssa.Parameter
					for _, param := range ssafn.Params {
						if param.Object() == obj {
							ssaobj = param
							break
						}
					}
					if ssaobj == nil {
						continue
					}
					refs := ssaobj.Referrers()
					if refs == nil {
						continue
					}
					if len(FilterDebug(*refs)) != 0 {
						continue
					}

					assigned := false
					ast.Inspect(body, func(node ast.Node) bool {
						assign, ok := node.(*ast.AssignStmt)
						if !ok {
							return true
						}
						for _, lhs := range assign.Lhs {
							ident, ok := lhs.(*ast.Ident)
							if !ok {
								continue
							}
							if ObjectOf(j, ident) == obj {
								assigned = true
								return false
							}
						}
						return true
					})
					if assigned {
						j.Errorf(arg, "argument %s is overwritten before first use", arg)
					}
				}
			}
			return true
		}
		Inspect(ssafn.Syntax(), fn)
	}
}

func (c *Checker) CheckIneffectiveLoop(j *lint.Job) {
	// This check detects some, but not all unconditional loop exits.
	// We give up in the following cases:
	//
	// - a goto anywhere in the loop. The goto might skip over our
	// return, and we don't check that it doesn't.
	//
	// - any nested, unlabelled continue, even if it is in another
	// loop or closure.
	fn := func(node ast.Node) bool {
		var body *ast.BlockStmt
		switch fn := node.(type) {
		case *ast.FuncDecl:
			body = fn.Body
		case *ast.FuncLit:
			body = fn.Body
		default:
			return true
		}
		if body == nil {
			return true
		}
		labels := map[*ast.Object]ast.Stmt{}
		ast.Inspect(body, func(node ast.Node) bool {
			label, ok := node.(*ast.LabeledStmt)
			if !ok {
				return true
			}
			labels[label.Label.Obj] = label.Stmt
			return true
		})

		ast.Inspect(body, func(node ast.Node) bool {
			var loop ast.Node
			var body *ast.BlockStmt
			switch node := node.(type) {
			case *ast.ForStmt:
				body = node.Body
				loop = node
			case *ast.RangeStmt:
				typ := TypeOf(j, node.X)
				if _, ok := typ.Underlying().(*types.Map); ok {
					// looping once over a map is a valid pattern for
					// getting an arbitrary element.
					return true
				}
				body = node.Body
				loop = node
			default:
				return true
			}
			if len(body.List) < 2 {
				// avoid flagging the somewhat common pattern of using
				// a range loop to get the first element in a slice,
				// or the first rune in a string.
				return true
			}
			var unconditionalExit ast.Node
			hasBranching := false
			for _, stmt := range body.List {
				switch stmt := stmt.(type) {
				case *ast.BranchStmt:
					switch stmt.Tok {
					case token.BREAK:
						if stmt.Label == nil || labels[stmt.Label.Obj] == loop {
							unconditionalExit = stmt
						}
					case token.CONTINUE:
						if stmt.Label == nil || labels[stmt.Label.Obj] == loop {
							unconditionalExit = nil
							return false
						}
					}
				case *ast.ReturnStmt:
					unconditionalExit = stmt
				case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.SwitchStmt, *ast.SelectStmt:
					hasBranching = true
				}
			}
			if unconditionalExit == nil || !hasBranching {
				return false
			}
			ast.Inspect(body, func(node ast.Node) bool {
				if branch, ok := node.(*ast.BranchStmt); ok {

					switch branch.Tok {
					case token.GOTO:
						unconditionalExit = nil
						return false
					case token.CONTINUE:
						if branch.Label != nil && labels[branch.Label.Obj] != loop {
							return true
						}
						unconditionalExit = nil
						return false
					}
				}
				return true
			})
			if unconditionalExit != nil {
				j.Errorf(unconditionalExit, "the surrounding loop is unconditionally terminated")
			}
			return true
		})
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckNilContext(j *lint.Job) {
	fn := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		if typ, ok := TypeOf(j, call.Args[0]).(*types.Basic); !ok || typ.Kind() != types.UntypedNil {
			return true
		}
		sig, ok := TypeOf(j, call.Fun).(*types.Signature)
		if !ok {
			return true
		}
		if sig.Params().Len() == 0 {
			return true
		}
		if !IsType(sig.Params().At(0).Type(), "context.Context") {
			return true
		}
		j.Errorf(call.Args[0],
			"do not pass a nil Context, even if a function permits it; pass context.TODO if you are unsure about which Context to use")
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckSeeker(j *lint.Job) {
	fn := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name != "Seek" {
			return true
		}
		if len(call.Args) != 2 {
			return true
		}
		arg0, ok := call.Args[Arg("(io.Seeker).Seek.offset")].(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch arg0.Sel.Name {
		case "SeekStart", "SeekCurrent", "SeekEnd":
		default:
			return true
		}
		pkg, ok := arg0.X.(*ast.Ident)
		if !ok {
			return true
		}
		if pkg.Name != "io" {
			return true
		}
		j.Errorf(call, "the first argument of io.Seeker is the offset, but an io.Seek* constant is being used instead")
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckIneffectiveAppend(j *lint.Job) {
	isAppend := func(ins ssa.Value) bool {
		call, ok := ins.(*ssa.Call)
		if !ok {
			return false
		}
		if call.Call.IsInvoke() {
			return false
		}
		if builtin, ok := call.Call.Value.(*ssa.Builtin); !ok || builtin.Name() != "append" {
			return false
		}
		return true
	}

	for _, ssafn := range j.Program.InitialFunctions {
		for _, block := range ssafn.Blocks {
			for _, ins := range block.Instrs {
				val, ok := ins.(ssa.Value)
				if !ok || !isAppend(val) {
					continue
				}

				isUsed := false
				visited := map[ssa.Instruction]bool{}
				var walkRefs func(refs []ssa.Instruction)
				walkRefs = func(refs []ssa.Instruction) {
				loop:
					for _, ref := range refs {
						if visited[ref] {
							continue
						}
						visited[ref] = true
						if _, ok := ref.(*ssa.DebugRef); ok {
							continue
						}
						switch ref := ref.(type) {
						case *ssa.Phi:
							walkRefs(*ref.Referrers())
						case *ssa.Sigma:
							walkRefs(*ref.Referrers())
						case ssa.Value:
							if !isAppend(ref) {
								isUsed = true
							} else {
								walkRefs(*ref.Referrers())
							}
						case ssa.Instruction:
							isUsed = true
							break loop
						}
					}
				}
				refs := val.Referrers()
				if refs == nil {
					continue
				}
				walkRefs(*refs)
				if !isUsed {
					j.Errorf(ins, "this result of append is never used, except maybe in other appends")
				}
			}
		}
	}
}

func (c *Checker) CheckConcurrentTesting(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		for _, block := range ssafn.Blocks {
			for _, ins := range block.Instrs {
				gostmt, ok := ins.(*ssa.Go)
				if !ok {
					continue
				}
				var fn *ssa.Function
				switch val := gostmt.Call.Value.(type) {
				case *ssa.Function:
					fn = val
				case *ssa.MakeClosure:
					fn = val.Fn.(*ssa.Function)
				default:
					continue
				}
				if fn.Blocks == nil {
					continue
				}
				for _, block := range fn.Blocks {
					for _, ins := range block.Instrs {
						call, ok := ins.(*ssa.Call)
						if !ok {
							continue
						}
						if call.Call.IsInvoke() {
							continue
						}
						callee := call.Call.StaticCallee()
						if callee == nil {
							continue
						}
						recv := callee.Signature.Recv()
						if recv == nil {
							continue
						}
						if !IsType(recv.Type(), "*testing.common") {
							continue
						}
						fn, ok := call.Call.StaticCallee().Object().(*types.Func)
						if !ok {
							continue
						}
						name := fn.Name()
						switch name {
						case "FailNow", "Fatal", "Fatalf", "SkipNow", "Skip", "Skipf":
						default:
							continue
						}
						j.Errorf(gostmt, "the goroutine calls T.%s, which must be called in the same goroutine as the test", name)
					}
				}
			}
		}
	}
}

func (c *Checker) CheckCyclicFinalizer(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		node := c.funcDescs.CallGraph.CreateNode(ssafn)
		for _, edge := range node.Out {
			if edge.Callee.Func.RelString(nil) != "runtime.SetFinalizer" {
				continue
			}
			arg0 := edge.Site.Common().Args[Arg("runtime.SetFinalizer.obj")]
			if iface, ok := arg0.(*ssa.MakeInterface); ok {
				arg0 = iface.X
			}
			unop, ok := arg0.(*ssa.UnOp)
			if !ok {
				continue
			}
			v, ok := unop.X.(*ssa.Alloc)
			if !ok {
				continue
			}
			arg1 := edge.Site.Common().Args[Arg("runtime.SetFinalizer.finalizer")]
			if iface, ok := arg1.(*ssa.MakeInterface); ok {
				arg1 = iface.X
			}
			mc, ok := arg1.(*ssa.MakeClosure)
			if !ok {
				continue
			}
			for _, b := range mc.Bindings {
				if b == v {
					pos := j.Program.DisplayPosition(mc.Fn.Pos())
					j.Errorf(edge.Site, "the finalizer closes over the object, preventing the finalizer from ever running (at %s)", pos)
				}
			}
		}
	}
}

func (c *Checker) CheckSliceOutOfBounds(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		for _, block := range ssafn.Blocks {
			for _, ins := range block.Instrs {
				ia, ok := ins.(*ssa.IndexAddr)
				if !ok {
					continue
				}
				if _, ok := ia.X.Type().Underlying().(*types.Slice); !ok {
					continue
				}
				sr, ok1 := c.funcDescs.Get(ssafn).Ranges[ia.X].(vrp.SliceInterval)
				idxr, ok2 := c.funcDescs.Get(ssafn).Ranges[ia.Index].(vrp.IntInterval)
				if !ok1 || !ok2 || !sr.IsKnown() || !idxr.IsKnown() || sr.Length.Empty() || idxr.Empty() {
					continue
				}
				if idxr.Lower.Cmp(sr.Length.Upper) >= 0 {
					j.Errorf(ia, "index out of bounds")
				}
			}
		}
	}
}

func (c *Checker) CheckDeferLock(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		for _, block := range ssafn.Blocks {
			instrs := FilterDebug(block.Instrs)
			if len(instrs) < 2 {
				continue
			}
			for i, ins := range instrs[:len(instrs)-1] {
				call, ok := ins.(*ssa.Call)
				if !ok {
					continue
				}
				if !IsCallTo(call.Common(), "(*sync.Mutex).Lock") && !IsCallTo(call.Common(), "(*sync.RWMutex).RLock") {
					continue
				}
				nins, ok := instrs[i+1].(*ssa.Defer)
				if !ok {
					continue
				}
				if !IsCallTo(&nins.Call, "(*sync.Mutex).Lock") && !IsCallTo(&nins.Call, "(*sync.RWMutex).RLock") {
					continue
				}
				if call.Common().Args[0] != nins.Call.Args[0] {
					continue
				}
				name := shortCallName(call.Common())
				alt := ""
				switch name {
				case "Lock":
					alt = "Unlock"
				case "RLock":
					alt = "RUnlock"
				}
				j.Errorf(nins, "deferring %s right after having locked already; did you mean to defer %s?", name, alt)
			}
		}
	}
}

func (c *Checker) CheckNaNComparison(j *lint.Job) {
	isNaN := func(v ssa.Value) bool {
		call, ok := v.(*ssa.Call)
		if !ok {
			return false
		}
		return IsCallTo(call.Common(), "math.NaN")
	}
	for _, ssafn := range j.Program.InitialFunctions {
		for _, block := range ssafn.Blocks {
			for _, ins := range block.Instrs {
				ins, ok := ins.(*ssa.BinOp)
				if !ok {
					continue
				}
				if isNaN(ins.X) || isNaN(ins.Y) {
					j.Errorf(ins, "no value is equal to NaN, not even NaN itself")
				}
			}
		}
	}
}

func (c *Checker) CheckInfiniteRecursion(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		node := c.funcDescs.CallGraph.CreateNode(ssafn)
		for _, edge := range node.Out {
			if edge.Callee != node {
				continue
			}
			if _, ok := edge.Site.(*ssa.Go); ok {
				// Recursively spawning goroutines doesn't consume
				// stack space infinitely, so don't flag it.
				continue
			}

			block := edge.Site.Block()
			canReturn := false
			for _, b := range ssafn.Blocks {
				if block.Dominates(b) {
					continue
				}
				if len(b.Instrs) == 0 {
					continue
				}
				if _, ok := b.Instrs[len(b.Instrs)-1].(*ssa.Return); ok {
					canReturn = true
					break
				}
			}
			if canReturn {
				continue
			}
			j.Errorf(edge.Site, "infinite recursive call")
		}
	}
}

func objectName(obj types.Object) string {
	if obj == nil {
		return "<nil>"
	}
	var name string
	if obj.Pkg() != nil && obj.Pkg().Scope().Lookup(obj.Name()) == obj {
		s := obj.Pkg().Path()
		if s != "" {
			name += s + "."
		}
	}
	name += obj.Name()
	return name
}

func isName(j *lint.Job, expr ast.Expr, name string) bool {
	var obj types.Object
	switch expr := expr.(type) {
	case *ast.Ident:
		obj = ObjectOf(j, expr)
	case *ast.SelectorExpr:
		obj = ObjectOf(j, expr.Sel)
	}
	return objectName(obj) == name
}

func (c *Checker) CheckLeakyTimeTick(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		if IsInMain(j, ssafn) || IsInTest(j, ssafn) {
			continue
		}
		for _, block := range ssafn.Blocks {
			for _, ins := range block.Instrs {
				call, ok := ins.(*ssa.Call)
				if !ok || !IsCallTo(call.Common(), "time.Tick") {
					continue
				}
				if c.funcDescs.Get(call.Parent()).Infinite {
					continue
				}
				j.Errorf(call, "using time.Tick leaks the underlying ticker, consider using it only in endless functions, tests and the main package, and use time.NewTicker here")
			}
		}
	}
}

func (c *Checker) CheckDoubleNegation(j *lint.Job) {
	fn := func(node ast.Node) bool {
		unary1, ok := node.(*ast.UnaryExpr)
		if !ok {
			return true
		}
		unary2, ok := unary1.X.(*ast.UnaryExpr)
		if !ok {
			return true
		}
		if unary1.Op != token.NOT || unary2.Op != token.NOT {
			return true
		}
		j.Errorf(unary1, "negating a boolean twice has no effect; is this a typo?")
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func hasSideEffects(node ast.Node) bool {
	dynamic := false
	ast.Inspect(node, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.CallExpr:
			dynamic = true
			return false
		case *ast.UnaryExpr:
			if node.Op == token.ARROW {
				dynamic = true
				return false
			}
		}
		return true
	})
	return dynamic
}

func (c *Checker) CheckRepeatedIfElse(j *lint.Job) {
	seen := map[ast.Node]bool{}

	var collectConds func(ifstmt *ast.IfStmt, inits []ast.Stmt, conds []ast.Expr) ([]ast.Stmt, []ast.Expr)
	collectConds = func(ifstmt *ast.IfStmt, inits []ast.Stmt, conds []ast.Expr) ([]ast.Stmt, []ast.Expr) {
		seen[ifstmt] = true
		if ifstmt.Init != nil {
			inits = append(inits, ifstmt.Init)
		}
		conds = append(conds, ifstmt.Cond)
		if elsestmt, ok := ifstmt.Else.(*ast.IfStmt); ok {
			return collectConds(elsestmt, inits, conds)
		}
		return inits, conds
	}
	fn := func(node ast.Node) bool {
		ifstmt, ok := node.(*ast.IfStmt)
		if !ok {
			return true
		}
		if seen[ifstmt] {
			return true
		}
		inits, conds := collectConds(ifstmt, nil, nil)
		if len(inits) > 0 {
			return true
		}
		for _, cond := range conds {
			if hasSideEffects(cond) {
				return true
			}
		}
		counts := map[string]int{}
		for _, cond := range conds {
			s := Render(j, cond)
			counts[s]++
			if counts[s] == 2 {
				j.Errorf(cond, "this condition occurs multiple times in this if/else if chain")
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckSillyBitwiseOps(j *lint.Job) {
	for _, ssafn := range j.Program.InitialFunctions {
		for _, block := range ssafn.Blocks {
			for _, ins := range block.Instrs {
				ins, ok := ins.(*ssa.BinOp)
				if !ok {
					continue
				}

				if c, ok := ins.Y.(*ssa.Const); !ok || c.Value == nil || c.Value.Kind() != constant.Int || c.Uint64() != 0 {
					continue
				}
				switch ins.Op {
				case token.AND, token.OR, token.XOR:
				default:
					// we do not flag shifts because too often, x<<0 is part
					// of a pattern, x<<0, x<<8, x<<16, ...
					continue
				}
				path, _ := astutil.PathEnclosingInterval(j.File(ins), ins.Pos(), ins.Pos())
				if len(path) == 0 {
					continue
				}
				if node, ok := path[0].(*ast.BinaryExpr); !ok || !IsZero(node.Y) {
					continue
				}

				switch ins.Op {
				case token.AND:
					j.Errorf(ins, "x & 0 always equals 0")
				case token.OR, token.XOR:
					j.Errorf(ins, "x %s 0 always equals x", ins.Op)
				}
			}
		}
	}
}

func (c *Checker) CheckNonOctalFileMode(j *lint.Job) {
	fn := func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		sig, ok := TypeOf(j, call.Fun).(*types.Signature)
		if !ok {
			return true
		}
		n := sig.Params().Len()
		var args []int
		for i := 0; i < n; i++ {
			typ := sig.Params().At(i).Type()
			if IsType(typ, "os.FileMode") {
				args = append(args, i)
			}
		}
		for _, i := range args {
			lit, ok := call.Args[i].(*ast.BasicLit)
			if !ok {
				continue
			}
			if len(lit.Value) == 3 &&
				lit.Value[0] != '0' &&
				lit.Value[0] >= '0' && lit.Value[0] <= '7' &&
				lit.Value[1] >= '0' && lit.Value[1] <= '7' &&
				lit.Value[2] >= '0' && lit.Value[2] <= '7' {

				v, err := strconv.ParseInt(lit.Value, 10, 64)
				if err != nil {
					continue
				}
				j.Errorf(call.Args[i], "file mode '%s' evaluates to %#o; did you mean '0%s'?", lit.Value, v, lit.Value)
			}
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) CheckPureFunctions(j *lint.Job) {
fnLoop:
	for _, ssafn := range j.Program.InitialFunctions {
		if IsInTest(j, ssafn) {
			params := ssafn.Signature.Params()
			for i := 0; i < params.Len(); i++ {
				param := params.At(i)
				if IsType(param.Type(), "*testing.B") {
					// Ignore discarded pure functions in code related
					// to benchmarks. Instead of matching BenchmarkFoo
					// functions, we match any function accepting a
					// *testing.B. Benchmarks sometimes call generic
					// functions for doing the actual work, and
					// checking for the parameter is a lot easier and
					// faster than analyzing call trees.
					continue fnLoop
				}
			}
		}

		for _, b := range ssafn.Blocks {
			for _, ins := range b.Instrs {
				ins, ok := ins.(*ssa.Call)
				if !ok {
					continue
				}
				refs := ins.Referrers()
				if refs == nil || len(FilterDebug(*refs)) > 0 {
					continue
				}
				callee := ins.Common().StaticCallee()
				if callee == nil {
					continue
				}
				if c.funcDescs.Get(callee).Pure && !c.funcDescs.Get(callee).Stub {
					j.Errorf(ins, "%s is a pure function but its return value is ignored", callee.Name())
					continue
				}
			}
		}
	}
}

func (c *Checker) isDeprecated(j *lint.Job, ident *ast.Ident) (bool, string) {
	obj := ObjectOf(j, ident)
	if obj.Pkg() == nil {
		return false, ""
	}
	alt := c.deprecatedObjs[obj]
	return alt != "", alt
}

func (c *Checker) CheckDeprecated(j *lint.Job) {
	// Selectors can appear outside of function literals, e.g. when
	// declaring package level variables.

	var ssafn *ssa.Function
	stack := 0
	fn := func(node ast.Node) bool {
		if node == nil {
			stack--
		} else {
			stack++
		}
		if stack == 1 {
			ssafn = nil
		}
		if fn, ok := node.(*ast.FuncDecl); ok {
			ssafn = j.Program.SSA.FuncValue(ObjectOf(j, fn.Name).(*types.Func))
		}
		sel, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}

		obj := ObjectOf(j, sel.Sel)
		if obj.Pkg() == nil {
			return true
		}
		nodePkg := j.NodePackage(node).Types
		if nodePkg == obj.Pkg() || obj.Pkg().Path()+"_test" == nodePkg.Path() {
			// Don't flag stuff in our own package
			return true
		}
		if ok, alt := c.isDeprecated(j, sel.Sel); ok {
			// Look for the first available alternative, not the first
			// version something was deprecated in. If a function was
			// deprecated in Go 1.6, an alternative has been available
			// already in 1.0, and we're targeting 1.2, it still
			// makes sense to use the alternative from 1.0, to be
			// future-proof.
			minVersion := deprecated.Stdlib[SelectorName(j, sel)].AlternativeAvailableSince
			if !IsGoVersion(j, minVersion) {
				return true
			}

			if ssafn != nil {
				if _, ok := c.deprecatedObjs[ssafn.Object()]; ok {
					// functions that are deprecated may use deprecated
					// symbols
					return true
				}
			}
			j.Errorf(sel, "%s is deprecated: %s", Render(j, sel), alt)
			return true
		}
		return true
	}
	for _, f := range j.Program.Files {
		ast.Inspect(f, fn)
	}
}

func (c *Checker) callChecker(rules map[string]CallCheck) func(j *lint.Job) {
	return func(j *lint.Job) {
		c.checkCalls(j, rules)
	}
}

func (c *Checker) checkCalls(j *lint.Job, rules map[string]CallCheck) {
	for _, ssafn := range j.Program.InitialFunctions {
		node := c.funcDescs.CallGraph.CreateNode(ssafn)
		for _, edge := range node.Out {
			callee := edge.Callee.Func
			obj, ok := callee.Object().(*types.Func)
			if !ok {
				continue
			}

			r, ok := rules[obj.FullName()]
			if !ok {
				continue
			}
			var args []*Argument
			ssaargs := edge.Site.Common().Args
			if callee.Signature.Recv() != nil {
				ssaargs = ssaargs[1:]
			}
			for _, arg := range ssaargs {
				if iarg, ok := arg.(*ssa.MakeInterface); ok {
					arg = iarg.X
				}
				vr := c.funcDescs.Get(edge.Site.Parent()).Ranges[arg]
				args = append(args, &Argument{Value: Value{arg, vr}})
			}
			call := &Call{
				Job:     j,
				Instr:   edge.Site,
				Args:    args,
				Checker: c,
				Parent:  edge.Site.Parent(),
			}
			r(call)
			for idx, arg := range call.Args {
				_ = idx
				for _, e := range arg.invalids {
					// path, _ := astutil.PathEnclosingInterval(f.File, edge.Site.Pos(), edge.Site.Pos())
					// if len(path) < 2 {
					// 	continue
					// }
					// astcall, ok := path[0].(*ast.CallExpr)
					// if !ok {
					// 	continue
					// }
					// j.Errorf(astcall.Args[idx], "%s", e)

					j.Errorf(edge.Site, "%s", e)
				}
			}
			for _, e := range call.invalids {
				j.Errorf(call.Instr.Common(), "%s", e)
			}
		}
	}
}

func shortCallName(call *ssa.CallCommon) string {
	if call.IsInvoke() {
		return ""
	}
	switch v := call.Value.(type) {
	case *ssa.Function:
		fn, ok := v.Object().(*types.Func)
		if !ok {
			return ""
		}
		return fn.Name()
	case *ssa.Builtin:
		return v.Name()
	}
	return ""
}

func (c *Checker) CheckWriterBufferModified(j *lint.Job) {
	// TODO(dh): this might be a good candidate for taint analysis.
	// Taint the argument as MUST_NOT_MODIFY, then propagate that
	// through functions like bytes.Split

	for _, ssafn := range j.Program.InitialFunctions {
		sig := ssafn.Signature
		if ssafn.Name() != "Write" || sig.Recv() == nil || sig.Params().Len() != 1 || sig.Results().Len() != 2 {
			continue
		}
		tArg, ok := sig.Params()
"""




```