Response:
The user has provided the second part of a Go source code file and is asking for a summary of its functionalities. Since this is the second part, I need to synthesize the information from both parts to provide a comprehensive overview.

**Part 1 Analysis (Implicit):**

Based on the naming conventions and the context of "inline/inl.go", I can infer that the first part likely deals with:

*   **Determining if a function is eligible for inlining:**  It would contain logic to check various conditions and constraints for inlining.
*   **Calculating the cost of inlining:**  This is crucial for deciding whether inlining is beneficial.
*   **Managing the inlining budget:**  There would be mechanisms to control how much inlining is done to avoid excessive code growth.
*   **Handling various inlining-related flags and debugging options.**

**Part 2 Analysis (Explicit):**

The provided code snippet focuses on:

*   **Detailed checks before inlining a call site:**  `canInlineCallExpr` performs several checks, including recursive calls, instrumentation settings, race detector settings, and repeated inlining within a recursion cycle.
*   **Creating an inlined call node:** `mkinlcall` replaces a regular function call with an `OINLCALL` node, which represents the inlined function body.
*   **Managing metadata for inlined closures:**  Special handling for direct calls to closures to ensure correct linker metadata.
*   **Handling side effects of inlined calls:**  `CalleeEffects` extracts initialization code from the inlined function.
*   **Post-processing of call sites:** `PostProcessCallSites` likely deals with gathering and potentially outputting data related to inlining decisions.
*   **Analyzing function properties for inlining:** `analyzeFuncProps` appears to integrate with profile-guided optimization.
*   **Utility functions:**  Helper functions like `pruneUnusedAutos`, `numNonClosures`, `doList`, `isIndexingCoverageCounter`, and `isAtomicCoverageCounterUpdate`. The coverage counter functions are specifically related to code coverage instrumentation.

**Synthesizing the Information:**

The overall goal of this file is to implement the inlining optimization in the Go compiler. It involves deciding which functions to inline, managing the process of replacing call sites with the function's body, and handling various edge cases and configurations.

**Plan for Generating the Response:**

1. Start with a general statement summarizing the file's purpose.
2. List the specific functionalities identified in Part 2.
3. Explain how these functionalities contribute to the overall inlining process.
4. Provide code examples for key functionalities like `canInlineCallExpr` and `mkinlcall`, including hypothetical inputs and expected outputs to illustrate the logic.
5. Discuss relevant command-line flags that influence inlining.
6. Mention potential pitfalls or common mistakes users might encounter (although the code itself doesn't directly expose user-facing errors, I can consider developer-level mistakes within the compiler).
7. Finally, provide a concise overall summary of the file's function, considering both parts.
这是 `go/src/cmd/compile/internal/inline/inl.go` 文件中关于内联实现的第二部分代码，主要负责**判断是否可以内联某个函数调用，并在确认可以内联后，生成代表内联调用的节点**。

结合之前的第一部分，我们可以归纳出 `inl.go` 文件的主要功能是**实现 Go 语言的函数内联优化**。

**第二部分代码的具体功能如下:**

1. **`canInlineCallExpr(callerfn *ir.Func, n *ir.CallExpr, callee *ir.Func, bigCaller, closureCalledOnce bool, log bool) (bool, int, bool)`:**
    *   **功能：** 详细检查一个函数调用 `n` 是否可以被内联到调用者 `callerfn` 中。
    *   **检查项包括：**
        *   Callee 函数是否被标记为不可内联 (`callee.NoInline()`)。
        *   Callee 函数的开销是否超过了调用者的最大内联开销 (`inlineCostOK`)。
        *   是否尝试递归地将函数内联到自身。
        *   在开启了 `-race` 或 `-d=checkptr` 标志时，是否尝试内联来自特定包（如 `runtime`）的函数。
        *   是否在同一个调用点递归地内联同一个函数，以避免无限递归。
    *   **输入：**
        *   `callerfn`: 调用者函数。
        *   `n`:  表示函数调用的 `ir.CallExpr` 节点。
        *   `callee`: 被调用函数。
        *   `bigCaller`:  一个布尔值，指示调用者是否是一个“大的”函数（可能影响内联策略）。
        *   `closureCalledOnce`: 一个布尔值，指示闭包是否只被调用一次。
        *   `log`:  一个布尔值，指示是否开启日志记录。
    *   **输出：**
        *   `bool`: 是否可以内联。
        *   `int`:  内联的“得分”（用于衡量内联的收益）。
        *   `bool`:  是否是“热点”调用。
    *   **代码推理示例：**
        ```go
        // 假设 callerFn 是一个简单的函数
        callerFn := &ir.Func{Nname: ir.NewNameAt(src.NoXPos, types.NewPkg("", "main"), ir.ONAME)}
        callerFn.Nname.Sym().Name = "callerFunc"

        // 假设 calleeFn 是一个简单的可内联函数
        calleeFn := &ir.Func{Nname: ir.NewNameAt(src.NoXPos, types.NewPkg("", "util"), ir.ONAME)}
        calleeFn.Nname.Sym().Name = "calleeFunc"
        calleeFn.SetInl(new(ir.Inl)) // 模拟 calleeFn 可以被内联

        // 假设 n 是调用 calleeFn 的调用表达式
        n := &ir.CallExpr{Fun: ir.NewNameAt(src.NoXPos, types.NewPkg("", "util"), ir.ONAME)}
        n.Fun.(*ir.Name).SetFunc(calleeFn)

        canInline, _, _ := canInlineCallExpr(callerFn, n, calleeFn, false, false, true)

        // 预期输出: canInline 为 true，因为 calleeFn 可以被内联，且没有其他阻止内联的条件
        fmt.Println(canInline) // Output: true
        ```

2. **`mkinlcall(callerfn *ir.Func, n *ir.CallExpr, fn *ir.Func, bigCaller, closureCalledOnce bool) *ir.InlinedCallExpr`:**
    *   **功能：**  如果 `canInlineCallExpr` 返回 `true`，则此函数将创建一个 `ir.InlinedCallExpr` 节点来替换原来的 `ir.CallExpr` 节点 `n`。`ir.InlinedCallExpr` 节点包含了被内联函数的代码。
    *   **处理闭包：**  特殊处理直接调用的闭包，确保链接器能够正确处理其元数据。
    *   **DWARF 信息：**  在生成 DWARF 调试信息时，记录内联信息。
    *   **日志输出：**  在开启 `-m` 标志时，输出内联相关的日志信息。
    *   **输入：**
        *   `callerfn`: 调用者函数。
        *   `n`:  表示函数调用的 `ir.CallExpr` 节点。
        *   `fn`: 被调用函数。
        *   `bigCaller`:  一个布尔值，指示调用者是否是一个“大的”函数。
        *   `closureCalledOnce`: 一个布尔值，指示闭包是否只被调用一次。
    *   **输出：**  指向新创建的 `ir.InlinedCallExpr` 节点的指针，如果不能内联则返回 `nil`。
    *   **代码推理示例：**
        ```go
        // 沿用 canInlineCallExpr 的示例
        callerFn := &ir.Func{Nname: ir.NewNameAt(src.NoXPos, types.NewPkg("", "main"), ir.ONAME)}
        callerFn.Nname.Sym().Name = "callerFunc"
        calleeFn := &ir.Func{Nname: ir.NewNameAt(src.NoXPos, types.NewPkg("", "util"), ir.ONAME)}
        calleeFn.Nname.Sym().Name = "calleeFunc"
        calleeFn.SetInl(new(ir.Inl))
        n := &ir.CallExpr{Fun: ir.NewNameAt(src.NoXPos, types.NewPkg("", "util"), ir.ONAME)}
        n.Fun.(*ir.Name).SetFunc(calleeFn)

        inlinedCall := mkinlcall(callerFn, n, calleeFn, false, false)

        // 预期输出: inlinedCall 不为 nil，并且其 Op() 应该是 ir.OINLCALL
        if inlinedCall != nil && inlinedCall.Op() == ir.OINLCALL {
            fmt.Println("Function inlined successfully")
        } else {
            fmt.Println("Function not inlined")
        }
        ```

3. **`CalleeEffects(init *ir.Nodes, callee ir.Node)`:**
    *   **功能：**  将 `callee` 表达式中可能产生的副作用（例如变量初始化）添加到 `init` 节点列表中。这在内联后需要确保副作用仍然被执行。
    *   **处理不同类型的表达式：**  可以处理 `ONAME`、`OCLOSURE`、`OMETHEXPR`、`OCONVNOP` 和 `OINLCALL` 等不同类型的表达式。
    *   **输入：**
        *   `init`:  一个 `ir.Nodes` 列表，用于存储副作用。
        *   `callee`:  表示被调用函数的表达式节点。
    *   **代码推理示例：**
        ```go
        // 假设一个简单的调用表达式
        callExpr := &ir.CallExpr{Op: ir.OCALLFUNC}

        // 假设被调用函数有一些初始化代码 (这里仅为演示，实际情况会更复杂)
        initNodes := ir.NewNodes(nil)
        calleeExpr := ir.NewNameAt(src.NoXPos, types.NewPkg("", "pkg"), ir.ONAME)
        ir. टेकInit(calleeExpr).Append(&ir.AssignStmt{}) // 模拟 callee 中有赋值操作

        CalleeEffects(initNodes, calleeExpr)

        // 预期输出: initNodes 中包含来自 calleeExpr 的初始化操作
        fmt.Println(len(initNodes.Slice())) // 输出: 1 (取决于 टेकInit 的实现)
        ```

4. **`pruneUnusedAutos(ll []*ir.Name, vis *hairyVisitor) []*ir.Name`:**
    *   **功能：**  从局部变量列表 `ll` 中移除未使用的自动变量（`PAUTO` 类的变量）。
    *   **使用 `hairyVisitor`：**  依赖于一个访问器 `vis` 来判断哪些局部变量被使用。
    *   **输入：**
        *   `ll`:  局部变量 `ir.Name` 切片。
        *   `vis`:  一个用于跟踪变量使用的 `hairyVisitor` 实例。
    *   **输出：**  移除未使用的自动变量后的 `ir.Name` 切片。

5. **`numNonClosures(list []*ir.Func) int`:**
    *   **功能：**  计算函数列表 `list` 中非闭包函数的数量。
    *   **输入：**  一个 `ir.Func` 指针切片。
    *   **输出：**  非闭包函数的数量。

6. **`doList(list []ir.Node, do func(ir.Node) bool) bool`:**
    *   **功能：**  迭代处理节点列表 `list`，对每个非 `nil` 节点执行 `do` 函数。如果 `do` 函数对任何节点返回 `true`，则 `doList` 也返回 `true`。
    *   **输入：**
        *   `list`:  `ir.Node` 切片。
        *   `do`:  一个接受 `ir.Node` 并返回 `bool` 的函数。
    *   **输出：**  如果 `do` 函数返回 `true` 则为 `true`，否则为 `false`。

7. **`isIndexingCoverageCounter(n ir.Node) bool`:**
    *   **功能：**  判断节点 `n` 是否是对代码覆盖率计数器数组进行索引操作。
    *   **检查节点类型和属性：**  检查是否是 `OINDEX` 操作，以及被索引的变量是否是数组类型的 `ONAME` 并且具有 `CoverageAuxVar` 属性。
    *   **输入：**  一个 `ir.Node` 接口。
    *   **输出：**  如果节点是对覆盖率计数器进行索引则为 `true`，否则为 `false`。

8. **`isAtomicCoverageCounterUpdate(cn *ir.CallExpr) bool`:**
    *   **功能：**  判断调用表达式 `cn` 是否是原子地更新代码覆盖率计数器的操作（例如调用 `sync/atomic.AddUint32` 或 `sync/atomic.StoreUint32`）。
    *   **检查函数名称和参数：**  检查调用的函数是否是 `sync/atomic.AddUint32` 或 `sync/atomic.StoreUint32`，并且第一个参数是对覆盖率计数器进行取地址操作。
    *   **输入：**  一个 `ir.CallExpr` 指针。
    *   **输出：**  如果是原子更新覆盖率计数器则为 `true`，否则为 `false`。

9. **`PostProcessCallSites(profile *pgoir.Profile)`:**
    *   **功能：**  对内联后的调用点进行后处理。
    *   **输出内联调用点得分：**  如果开启了 `Debug.DumpInlCallSiteScores` 调试标志，则会输出每个调用点的内联得分。
    *   **与 PGO 集成：**  可能与 Profile-Guided Optimization (PGO) 相关，使用 `pgoir.Profile` 来辅助决策。
    *   **输入：**  一个 `pgoir.Profile` 指针。

10. **`analyzeFuncProps(fn *ir.Func, p *pgoir.Profile)`:**
    *   **功能：**  分析函数的属性，用于内联决策。
    *   **与 PGO 集成：**  使用 PGO 数据 (`pgoir.Profile`) 来辅助分析。
    *   **调用其他内联分析函数：**  例如 `CanInline` 和 `inlineBudget`。
    *   **输入：**
        *   `fn`:  要分析的函数 `ir.Func` 指针。
        *   `p`:  PGO 数据 `pgoir.Profile` 指针。

**命令行参数的影响：**

*   **`-m`:**  控制内联相关的日志输出级别。`-m` 会打印基本的内联决策，`-m=2` 或更高会打印更详细的信息，例如内联前后的 AST 结构。
*   **`-l`:**  禁用内联。
*   **`-l=pattern`:**  禁用匹配特定模式的函数的内联。
*   **`-gcflags=-d=inlbudget=N`:**  设置内联预算，影响哪些函数可以被内联。
*   **`-gcflags=-d=dumpinlinetree=N`:**  输出内联树的结构。
*   **`-race`:** 开启竞态检测，会影响某些 runtime 包函数的内联。
*   **`-d=checkptr`:** 开启指针检查，也会影响某些 runtime 包函数的内联。
*   **`-d=dumpinlcallsitescores`:**  输出内联调用点的得分信息。
*   **构建标签 (`//go:build ...`)**:  某些构建标签可能会影响内联行为。

**使用者易犯错的点 (作为 Go 语言开发者，而非 `cmd/compile` 的开发者):**

虽然用户不能直接控制这些底层的内联逻辑，但了解其工作原理可以帮助理解性能特性：

*   **过度依赖内联进行性能优化：**  内联不是万能的，过度依赖可能会导致代码膨胀，反而降低性能。
*   **不理解内联的限制：**  某些函数由于大小、复杂性或特定的语言特性（如 `select` 语句、`for...range` 循环在某些情况下）可能无法被内联。
*   **编写过于庞大的函数：**  大的函数更难被内联，因此将功能分解为小的、可复用的函数可能更有利于内联优化。
*   **忽略 PGO 的作用：**  使用 PGO 可以提供更准确的性能数据，帮助编译器做出更优的内联决策。

**总结 `inl.go` 的功能 (结合第一部分):**

`go/src/cmd/compile/internal/inline/inl.go` 文件是 Go 编译器中负责实现函数内联优化的核心组件。它定义了内联的策略、成本模型、以及执行内联的具体步骤。

**主要功能包括：**

*   **判断函数是否可以被内联：**  通过各种检查，例如函数大小、复杂性、递归调用、是否包含禁止内联的语句等。
*   **计算内联的成本和收益：**  根据函数的大小、调用频率等因素评估内联的价值。
*   **管理内联预算：**  控制内联的程度，避免过度内联导致代码膨胀。
*   **执行内联操作：**  将调用点的函数体替换为被调用函数的代码。
*   **处理内联过程中的各种细节：**  例如变量重命名、副作用处理、闭包处理、调试信息生成等。
*   **与 Profile-Guided Optimization (PGO) 集成：**  利用性能 профилирования 数据来指导内联决策。
*   **提供命令行标志来控制内联行为和输出调试信息。**

总而言之，`inl.go` 是 Go 编译器进行函数内联优化的关键实现，旨在提升程序的执行效率。

### 提示词
```
这是路径为go/src/cmd/compile/internal/inline/inl.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```go
, "inline", ir.FuncName(callerfn),
				fmt.Sprintf("%s cannot be inlined", ir.PkgFuncName(callee)))
		}
		return false, 0, false
	}

	ok, maxCost, callSiteScore, hot := inlineCostOK(n, callerfn, callee, bigCaller, closureCalledOnce)
	if !ok {
		// callee cost too high for this call site.
		if log && logopt.Enabled() {
			logopt.LogOpt(n.Pos(), "cannotInlineCall", "inline", ir.FuncName(callerfn),
				fmt.Sprintf("cost %d of %s exceeds max caller cost %d", callee.Inl.Cost, ir.PkgFuncName(callee), maxCost))
		}
		return false, 0, false
	}

	if callee == callerfn {
		// Can't recursively inline a function into itself.
		if log && logopt.Enabled() {
			logopt.LogOpt(n.Pos(), "cannotInlineCall", "inline", fmt.Sprintf("recursive call to %s", ir.FuncName(callerfn)))
		}
		return false, 0, false
	}

	if base.Flag.Cfg.Instrumenting && types.IsNoInstrumentPkg(callee.Sym().Pkg) {
		// Runtime package must not be instrumented.
		// Instrument skips runtime package. However, some runtime code can be
		// inlined into other packages and instrumented there. To avoid this,
		// we disable inlining of runtime functions when instrumenting.
		// The example that we observed is inlining of LockOSThread,
		// which lead to false race reports on m contents.
		if log && logopt.Enabled() {
			logopt.LogOpt(n.Pos(), "cannotInlineCall", "inline", ir.FuncName(callerfn),
				fmt.Sprintf("call to runtime function %s in instrumented build", ir.PkgFuncName(callee)))
		}
		return false, 0, false
	}

	if base.Flag.Race && types.IsNoRacePkg(callee.Sym().Pkg) {
		if log && logopt.Enabled() {
			logopt.LogOpt(n.Pos(), "cannotInlineCall", "inline", ir.FuncName(callerfn),
				fmt.Sprintf(`call to into "no-race" package function %s in race build`, ir.PkgFuncName(callee)))
		}
		return false, 0, false
	}

	if base.Debug.Checkptr != 0 && types.IsRuntimePkg(callee.Sym().Pkg) {
		// We don't instrument runtime packages for checkptr (see base/flag.go).
		if log && logopt.Enabled() {
			logopt.LogOpt(n.Pos(), "cannotInlineCall", "inline", ir.FuncName(callerfn),
				fmt.Sprintf(`call to into runtime package function %s in -d=checkptr build`, ir.PkgFuncName(callee)))
		}
		return false, 0, false
	}

	// Check if we've already inlined this function at this particular
	// call site, in order to stop inlining when we reach the beginning
	// of a recursion cycle again. We don't inline immediately recursive
	// functions, but allow inlining if there is a recursion cycle of
	// many functions. Most likely, the inlining will stop before we
	// even hit the beginning of the cycle again, but this catches the
	// unusual case.
	parent := base.Ctxt.PosTable.Pos(n.Pos()).Base().InliningIndex()
	sym := callee.Linksym()
	for inlIndex := parent; inlIndex >= 0; inlIndex = base.Ctxt.InlTree.Parent(inlIndex) {
		if base.Ctxt.InlTree.InlinedFunction(inlIndex) == sym {
			if log {
				if base.Flag.LowerM > 1 {
					fmt.Printf("%v: cannot inline %v into %v: repeated recursive cycle\n", ir.Line(n), callee, ir.FuncName(callerfn))
				}
				if logopt.Enabled() {
					logopt.LogOpt(n.Pos(), "cannotInlineCall", "inline", ir.FuncName(callerfn),
						fmt.Sprintf("repeated recursive cycle to %s", ir.PkgFuncName(callee)))
				}
			}
			return false, 0, false
		}
	}

	return true, callSiteScore, hot
}

// mkinlcall returns an OINLCALL node that can replace OCALLFUNC n, or
// nil if it cannot be inlined. callerfn is the function that contains
// n, and fn is the function being called.
//
// The result of mkinlcall MUST be assigned back to n, e.g.
//
//	n.Left = mkinlcall(n.Left, fn, isddd)
func mkinlcall(callerfn *ir.Func, n *ir.CallExpr, fn *ir.Func, bigCaller, closureCalledOnce bool) *ir.InlinedCallExpr {
	ok, score, hot := canInlineCallExpr(callerfn, n, fn, bigCaller, closureCalledOnce, true)
	if !ok {
		return nil
	}
	if hot {
		hasHotCall[callerfn] = struct{}{}
	}
	typecheck.AssertFixedCall(n)

	parent := base.Ctxt.PosTable.Pos(n.Pos()).Base().InliningIndex()
	sym := fn.Linksym()
	inlIndex := base.Ctxt.InlTree.Add(parent, n.Pos(), sym, ir.FuncName(fn))

	closureInitLSym := func(n *ir.CallExpr, fn *ir.Func) {
		// The linker needs FuncInfo metadata for all inlined
		// functions. This is typically handled by gc.enqueueFunc
		// calling ir.InitLSym for all function declarations in
		// typecheck.Target.Decls (ir.UseClosure adds all closures to
		// Decls).
		//
		// However, closures in Decls are ignored, and are
		// instead enqueued when walk of the calling function
		// discovers them.
		//
		// This presents a problem for direct calls to closures.
		// Inlining will replace the entire closure definition with its
		// body, which hides the closure from walk and thus suppresses
		// symbol creation.
		//
		// Explicitly create a symbol early in this edge case to ensure
		// we keep this metadata.
		//
		// TODO: Refactor to keep a reference so this can all be done
		// by enqueueFunc.

		if n.Op() != ir.OCALLFUNC {
			// Not a standard call.
			return
		}
		if n.Fun.Op() != ir.OCLOSURE {
			// Not a direct closure call.
			return
		}

		clo := n.Fun.(*ir.ClosureExpr)
		if !clo.Func.IsClosure() {
			// enqueueFunc will handle non closures anyways.
			return
		}

		ir.InitLSym(fn, true)
	}

	closureInitLSym(n, fn)

	if base.Flag.GenDwarfInl > 0 {
		if !sym.WasInlined() {
			base.Ctxt.DwFixups.SetPrecursorFunc(sym, fn)
			sym.Set(obj.AttrWasInlined, true)
		}
	}

	if base.Flag.LowerM != 0 {
		if buildcfg.Experiment.NewInliner {
			fmt.Printf("%v: inlining call to %v with score %d\n",
				ir.Line(n), fn, score)
		} else {
			fmt.Printf("%v: inlining call to %v\n", ir.Line(n), fn)
		}
	}
	if base.Flag.LowerM > 2 {
		fmt.Printf("%v: Before inlining: %+v\n", ir.Line(n), n)
	}

	res := InlineCall(callerfn, n, fn, inlIndex)

	if res == nil {
		base.FatalfAt(n.Pos(), "inlining call to %v failed", fn)
	}

	if base.Flag.LowerM > 2 {
		fmt.Printf("%v: After inlining %+v\n\n", ir.Line(res), res)
	}

	if inlheur.Enabled() {
		inlheur.UpdateCallsiteTable(callerfn, n, res)
	}

	return res
}

// CalleeEffects appends any side effects from evaluating callee to init.
func CalleeEffects(init *ir.Nodes, callee ir.Node) {
	for {
		init.Append(ir.TakeInit(callee)...)

		switch callee.Op() {
		case ir.ONAME, ir.OCLOSURE, ir.OMETHEXPR:
			return // done

		case ir.OCONVNOP:
			conv := callee.(*ir.ConvExpr)
			callee = conv.X

		case ir.OINLCALL:
			ic := callee.(*ir.InlinedCallExpr)
			init.Append(ic.Body.Take()...)
			callee = ic.SingleResult()

		default:
			base.FatalfAt(callee.Pos(), "unexpected callee expression: %v", callee)
		}
	}
}

func pruneUnusedAutos(ll []*ir.Name, vis *hairyVisitor) []*ir.Name {
	s := make([]*ir.Name, 0, len(ll))
	for _, n := range ll {
		if n.Class == ir.PAUTO {
			if !vis.usedLocals.Has(n) {
				// TODO(mdempsky): Simplify code after confident that this
				// never happens anymore.
				base.FatalfAt(n.Pos(), "unused auto: %v", n)
				continue
			}
		}
		s = append(s, n)
	}
	return s
}

// numNonClosures returns the number of functions in list which are not closures.
func numNonClosures(list []*ir.Func) int {
	count := 0
	for _, fn := range list {
		if fn.OClosure == nil {
			count++
		}
	}
	return count
}

func doList(list []ir.Node, do func(ir.Node) bool) bool {
	for _, x := range list {
		if x != nil {
			if do(x) {
				return true
			}
		}
	}
	return false
}

// isIndexingCoverageCounter returns true if the specified node 'n' is indexing
// into a coverage counter array.
func isIndexingCoverageCounter(n ir.Node) bool {
	if n.Op() != ir.OINDEX {
		return false
	}
	ixn := n.(*ir.IndexExpr)
	if ixn.X.Op() != ir.ONAME || !ixn.X.Type().IsArray() {
		return false
	}
	nn := ixn.X.(*ir.Name)
	// CoverageAuxVar implies either a coverage counter or a package
	// ID; since the cover tool never emits code to index into ID vars
	// this is effectively testing whether nn is a coverage counter.
	return nn.CoverageAuxVar()
}

// isAtomicCoverageCounterUpdate examines the specified node to
// determine whether it represents a call to sync/atomic.AddUint32 to
// increment a coverage counter.
func isAtomicCoverageCounterUpdate(cn *ir.CallExpr) bool {
	if cn.Fun.Op() != ir.ONAME {
		return false
	}
	name := cn.Fun.(*ir.Name)
	if name.Class != ir.PFUNC {
		return false
	}
	fn := name.Sym().Name
	if name.Sym().Pkg.Path != "sync/atomic" ||
		(fn != "AddUint32" && fn != "StoreUint32") {
		return false
	}
	if len(cn.Args) != 2 || cn.Args[0].Op() != ir.OADDR {
		return false
	}
	adn := cn.Args[0].(*ir.AddrExpr)
	v := isIndexingCoverageCounter(adn.X)
	return v
}

func PostProcessCallSites(profile *pgoir.Profile) {
	if base.Debug.DumpInlCallSiteScores != 0 {
		budgetCallback := func(fn *ir.Func, prof *pgoir.Profile) (int32, bool) {
			v := inlineBudget(fn, prof, false, false)
			return v, v == inlineHotMaxBudget
		}
		inlheur.DumpInlCallSiteScores(profile, budgetCallback)
	}
}

func analyzeFuncProps(fn *ir.Func, p *pgoir.Profile) {
	canInline := func(fn *ir.Func) { CanInline(fn, p) }
	budgetForFunc := func(fn *ir.Func) int32 {
		return inlineBudget(fn, p, true, false)
	}
	inlheur.AnalyzeFunc(fn, canInline, budgetForFunc, inlineMaxBudget)
}
```