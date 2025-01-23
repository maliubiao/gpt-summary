Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Initial Understanding - The Package and Purpose:** The code is in `go/src/cmd/compile/internal/inline/inlheur/scoring.go`. This immediately suggests it's part of the Go compiler, specifically the inliner, and focuses on *scoring* callsites. The package name `inlheur` reinforces this, hinting at inlining heuristics.

2. **Core Data Structure - `scoreAdjustTyp` and its Constants:** The `scoreAdjustTyp` and its associated constants are central. These constants represent different scenarios where the inliner might adjust the score of a function call. The comments categorize these adjustments nicely: callsite context, passed values, and returned values. The "must" and "may" distinction within categories 2 and 3 is important.

3. **Score Adjustment Values - `adjValues`:**  The `adjValues` map holds the numerical adjustments for each `scoreAdjustTyp`. The comment explicitly mentions the arbitrary nature of these values and the desire for future tuning. This is a key piece of information for understanding *how* the scoring works.

4. **Configuration - `-d=inlscoreadj`:** The `SetupScoreAdjustments` function reveals that these adjustment values can be overridden via the `-d=inlscoreadj` debugging flag. This is a crucial detail for anyone trying to experiment with or debug the inliner's behavior. The parsing logic in `parseScoreAdj` is important to understand how this flag works.

5. **The `CallSite` struct and its `computeCallSiteScore` method:** Although the `CallSite` struct itself isn't fully defined in this snippet, the `computeCallSiteScore` method is present. This method is the heart of the scoring logic. It takes a `CallSite`, information about the called function (`calleeProps`), and calculates a score based on the `adjValues` and the specific conditions at the callsite. The step-by-step adjustments based on `csflags` and `argProps` are crucial.

6. **"Must" vs. "May" Logic:** The `mayMustAdj`, `isMay`, `isMust`, `mayToMust`, and `mustToMay` functions handle the "must" and "may" logic. The comments explain the intent: "must" adjustments are guaranteed if the call executes, while "may" adjustments have control flow that could bypass the benefit. The logic for promoting "may" to "must" and avoiding double application is important.

7. **`LargestNegativeScoreAdjustment` and `LargestPositiveScoreAdjustment`:** These functions provide estimates of the maximum possible score adjustments. `LargestNegativeScoreAdjustment` seems designed to help determine if a function *could* potentially be inlined after scoring, even if its initial cost is high. `LargestPositiveScoreAdjustment` is simpler, reflecting fewer positive adjustments.

8. **`ScoreCalls` and `scoreCallsRegion`:**  `ScoreCalls` is the entry point for scoring calls within a function. It handles the setup of the `callSiteTab`. `scoreCallsRegion` performs the actual scoring, iterating through the callsites and applying the `computeCallSiteScore` method. The caching mechanism using `scoreCallsCache` is an optimization.

9. **`DumpInlCallSiteScores`:** This function provides debugging output when `-d=dumpinlcallsitescores` is enabled. It summarizes the scoring results for each callsite, including the original cost, adjustments, and final score. The status indicators ("PROMOTED," "DEMOTED," PGO) are helpful for understanding the impact of the scoring heuristics.

10. **Inferring Functionality and Examples:** Based on the understanding of the code, we can deduce that it's about fine-tuning the inlining decisions. The examples should illustrate the different scoring adjustments. For instance, a call inside a loop gets penalized, a call on a panic path gets a bonus, and passing a constant to an `if` condition gets penalized (as it might lead to better optimization in the caller).

11. **Command-Line Arguments:** The `-d=inlscoreadj` flag is the primary command-line argument handled here. The explanation needs to cover the syntax (comma-separated `adj:value` pairs) and its effect on overriding the default `adjValues`.

12. **Common Mistakes:**  Thinking about potential errors a user might make involves misunderstanding the "must" and "may" logic, misconfiguring the `-d=inlscoreadj` flag, or expecting immediate performance changes without understanding the interplay of different inlining heuristics.

By following this structured approach, breaking down the code into its components, understanding the purpose of each part, and connecting the pieces together, we can arrive at a comprehensive analysis of the provided Go code snippet. The key is to pay attention to the comments, variable names, and function signatures to infer the intended behavior.
这段 Go 语言代码是 Go 编译器内联优化器 (`inliner`) 的一部分，专门负责**计算和调整函数调用点（callsite）的分数**，以决定是否应该将被调用函数内联到调用函数中。

更具体地说，它的功能是：

1. **定义了不同的评分调整类型 (`scoreAdjustTyp`)**:  这些类型代表了在不同情况下如何调整调用点的分数。这些情况可以基于调用点的上下文（例如，是否在 panic 路径中），传递给被调用函数的参数的特性（例如，是否传递了常量），以及被调用函数的返回值特性。

2. **维护了每种调整类型的具体数值 (`adjValues`)**:  这是一个 `map`，将每种 `scoreAdjustTyp` 映射到一个整数值。这个值代表了在相应情况下，调用点的分数应该增加还是减少多少。 这些数值是启发式的，可以通过调试标志 `-d=inlscoreadj` 进行自定义。

3. **提供了设置和解析调试选项的功能 (`SetupScoreAdjustments`, `parseScoreAdj`)**: 允许开发者通过命令行参数 `-d=inlscoreadj` 来修改各种评分调整类型的具体数值，从而影响内联决策。

4. **实现了计算调用点分数的核心逻辑 (`computeCallSiteScore`)**: 这个方法根据被调用函数的开销（`callee.Inl.Cost`）和各种启发式规则来计算调用点的最终分数。它会检查调用点的上下文和参数属性，并根据 `adjValues` 中的配置调整分数。

5. **实现了根据函数返回值调整调用点分数的功能 (`examineCallResults`, `rescoreBasedOnCallResultUses`)**:  虽然这段代码中 `examineCallResults` 和 `rescoreBasedOnCallResultUses` 的具体实现没有完全展示，但根据注释和变量名可以推断，它会分析被调用函数的返回值，如果返回值具有某些特性（例如，总是返回相同的常量或函数），则会进一步调整调用点的分数。

6. **提供了估计最大负面和正面评分调整的能力 (`LargestNegativeScoreAdjustment`, `LargestPositiveScoreAdjustment`)**: 这可以用于粗略地判断一个函数是否有可能被内联，即使其原始开销较高。

7. **维护和管理调用点信息的缓存 (`callSiteTab`, `scoreCallsCache`)**: 用于存储和复用已经计算过的调用点信息，提高编译效率。

8. **提供了在调试模式下输出调用点分数信息的功能 (`DumpInlCallSiteScores`)**:  当设置了 `-d=dumpinlcallsitescores` 调试标志时，会输出每个调用点的最终分数、调整值、状态以及相关的启发式标志，方便开发者理解内联决策过程。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 编译器**内联优化**功能实现的核心部分。内联是将一个函数的代码直接插入到调用它的地方，可以减少函数调用的开销，从而提高程序性能。然而，内联并非总是好的，内联过多的代码可能会导致代码膨胀，增加编译时间和二进制文件大小，甚至可能降低性能（例如，增加指令缓存压力）。

这段代码通过评分机制来权衡内联的利弊。每个函数调用点都有一个分数，分数越低，内联的可能性越高。通过各种启发式规则调整分数，可以更智能地做出内联决策。

**Go 代码举例说明：**

假设有以下 Go 代码：

```go
package main

import "fmt"

func add(a, b int) int {
	return a + b
}

func process(x int) {
	if x > 10 {
		fmt.Println("x is large")
	}
	result := add(x, 5) // 调用点
	fmt.Println("result:", result)
}

func main() {
	process(15)
	process(5)
}
```

当编译器编译 `process` 函数时，会遇到 `add(x, 5)` 这个调用点。`scoring.go` 中的代码会参与到这个调用点的评分过程中。

**假设的输入与输出 (针对 `add(x, 5)` 调用点):**

* **输入 (部分):**
    * `callee`:  `add` 函数的 IR 节点
    * `call`: `add(x, 5)` 这个调用表达式的 IR 节点
    * `csflags`:  可能包含一些标志，例如 `CallSiteInLoop` (如果调用发生在循环内)
    * `calleeProps` (针对 `add` 函数): 可能包含 `add` 函数的开销信息 (例如，代码大小)
    * `cs.ArgProps[0]` (针对参数 `x`):  可能包含 `ActualExprIsNotConstant`
    * `cs.ArgProps[1]` (针对参数 `5`):  可能包含 `ActualExprConstant`
    * `calleeProps.ParamFlags[0]` (针对 `add` 的参数 `a`):  可能包含 `ParamFeedsArithmetic`
    * `calleeProps.ParamFlags[1]` (针对 `add` 的参数 `b`):  可能包含 `ParamFeedsArithmetic`

* **输出 (部分):**
    * `cs.Score`:  调用点的最终分数 (例如，根据 `add` 的开销和可能的调整值计算得到)
    * `cs.ScoreMask`:  记录了哪些评分调整被应用了 (例如，如果 `5` 是常量，可能会应用 `passConstTo...` 相关的调整)

**代码推理示例:**

假设 `add` 函数的初始开销是 10。

1. **初始分数:** `score = 10` (来自 `add.Inl.Cost`)
2. **参数分析:**
   * 第一个参数 `x` 不是常量，所以不会应用 `passConstToIfAdj` 等调整。
   * 第二个参数 `5` 是常量。如果 `add` 函数的参数被用于 `if` 或 `switch` 语句（虽然在这个例子中没有），则可能会应用 `passConstToIfAdj` 等调整来降低分数（鼓励内联）。 假设 `add` 的参数没有直接用于 `if` 或 `switch`，则这里不会有调整。
3. **上下文分析:** 假设 `add(x, 5)` 的调用不在 `panic` 路径或 `init` 函数中，也不在循环中，则 `panicPathAdj`, `initFuncAdj`, `inLoopAdj` 不会影响分数。

最终，`cs.Score` 可能仍然是 10。如果 `process` 函数的内联预算允许，那么 `add` 函数可能会被内联到 `process` 中。

**命令行参数的具体处理：**

`-d=inlscoreadj` 允许开发者自定义评分调整值。它的格式是 `/` 分隔的 `adj:value` 对。

例如：

* `-d=inlscoreadj=inLoopAdj=0`:  将 `inLoopAdj` 的值设置为 0，这意味着在循环中调用函数不再会降低其内联优先级。
* `-d=inlscoreadj=panicPathAdj=100/passConstToIfAdj=-50`: 将 `panicPathAdj` 的值设置为 100，`passConstToIfAdj` 的值设置为 -50。这意味着在 panic 路径中的调用会被更强烈地优先内联，而传递常量给 `if` 语句的调用会被更强烈地鼓励内联。

`SetupScoreAdjustments` 函数会解析这个字符串，并调用 `parseScoreAdj` 来更新 `adjValues` map。`parseScoreAdj` 会将字符串分割成 clauses，然后将每个 clause 分割成调整类型和值，并将值转换为整数，更新 `adjValues`。如果格式不正确，会抛出错误信息。

**使用者易犯错的点：**

1. **误解调整类型的含义：**  不理解每个 `scoreAdjustTyp` 代表的具体场景，导致错误地调整了不相关的分数。例如，错误地认为 `passConstToIfAdj` 适用于所有传递常量的场景，而实际上它只针对传递常量给 `if` 或 `switch` 语句的情况。

   **例子：** 用户可能认为增加 `passConstToIfAdj` 的值会阻止所有传递常量的函数被内联，但实际上它只影响特定情况。

2. **设置了不合理的调整值：**  将调整值设置得过大或过小，导致内联决策出现偏差。例如，将所有负向调整的值都设置为非常小，可能会导致过度内联，反而降低性能。

   **例子：** 用户将 `inLoopAdj` 设置为非常大的负数，导致即使是很小的函数在循环中调用也不会被内联。

3. **忘记不同调整类型的优先级 ("must" vs. "may")：**  "must" 类型的调整是无条件的，而 "may" 类型的调整只在特定控制流下生效。不理解这一点可能会导致对最终分数的预测出现偏差。

   **例子：** 用户可能同时设置了 "must" 和 "may" 版本的调整，但没有意识到 "must" 版本会覆盖 "may" 版本。

4. **不了解调整值的相互影响：**  多个调整可能会同时作用于同一个调用点，最终的分数是所有调整值的累加。用户可能只关注单个调整的影响，而忽略了整体的影响。

   **例子：** 一个调用点可能同时满足 `inLoopAdj` 和 `panicPathAdj` 的条件，最终的分数调整是这两个值的和。

总而言之，这段代码是 Go 编译器内联优化的重要组成部分，它通过一套启发式的评分机制来指导内联决策。理解这些评分调整类型和它们的值，以及如何通过命令行参数进行配置，对于深入理解 Go 编译器的内联行为至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/inline/inlheur/scoring.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package inlheur

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/pgoir"
	"cmd/compile/internal/types"
	"cmp"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

// These constants enumerate the set of possible ways/scenarios
// in which we'll adjust the score of a given callsite.
type scoreAdjustTyp uint

// These constants capture the various ways in which the inliner's
// scoring phase can adjust a callsite score based on heuristics. They
// fall broadly into three categories:
//
// 1) adjustments based solely on the callsite context (ex: call
// appears on panic path)
//
// 2) adjustments that take into account specific interesting values
// passed at a call site (ex: passing a constant that could result in
// cprop/deadcode in the caller)
//
// 3) adjustments that take into account values returned from the call
// at a callsite (ex: call always returns the same inlinable function,
// and return value flows unmodified into an indirect call)
//
// For categories 2 and 3 above, each adjustment can have either a
// "must" version and a "may" version (but not both). Here the idea is
// that in the "must" version the value flow is unconditional: if the
// callsite executes, then the condition we're interested in (ex:
// param feeding call) is guaranteed to happen. For the "may" version,
// there may be control flow that could cause the benefit to be
// bypassed.
const (
	// Category 1 adjustments (see above)
	panicPathAdj scoreAdjustTyp = (1 << iota)
	initFuncAdj
	inLoopAdj

	// Category 2 adjustments (see above).
	passConstToIfAdj
	passConstToNestedIfAdj
	passConcreteToItfCallAdj
	passConcreteToNestedItfCallAdj
	passFuncToIndCallAdj
	passFuncToNestedIndCallAdj
	passInlinableFuncToIndCallAdj
	passInlinableFuncToNestedIndCallAdj

	// Category 3 adjustments.
	returnFeedsConstToIfAdj
	returnFeedsFuncToIndCallAdj
	returnFeedsInlinableFuncToIndCallAdj
	returnFeedsConcreteToInterfaceCallAdj

	sentinelScoreAdj // sentinel; not a real adjustment
)

// This table records the specific values we use to adjust call
// site scores in a given scenario.
// NOTE: these numbers are chosen very arbitrarily; ideally
// we will go through some sort of turning process to decide
// what value for each one produces the best performance.

var adjValues = map[scoreAdjustTyp]int{
	panicPathAdj:                          40,
	initFuncAdj:                           20,
	inLoopAdj:                             -5,
	passConstToIfAdj:                      -20,
	passConstToNestedIfAdj:                -15,
	passConcreteToItfCallAdj:              -30,
	passConcreteToNestedItfCallAdj:        -25,
	passFuncToIndCallAdj:                  -25,
	passFuncToNestedIndCallAdj:            -20,
	passInlinableFuncToIndCallAdj:         -45,
	passInlinableFuncToNestedIndCallAdj:   -40,
	returnFeedsConstToIfAdj:               -15,
	returnFeedsFuncToIndCallAdj:           -25,
	returnFeedsInlinableFuncToIndCallAdj:  -40,
	returnFeedsConcreteToInterfaceCallAdj: -25,
}

// SetupScoreAdjustments interprets the value of the -d=inlscoreadj
// debugging option, if set. The value of this flag is expected to be
// a series of "/"-separated clauses of the form adj1:value1. Example:
// -d=inlscoreadj=inLoopAdj=0/passConstToIfAdj=-99
func SetupScoreAdjustments() {
	if base.Debug.InlScoreAdj == "" {
		return
	}
	if err := parseScoreAdj(base.Debug.InlScoreAdj); err != nil {
		base.Fatalf("malformed -d=inlscoreadj argument %q: %v",
			base.Debug.InlScoreAdj, err)
	}
}

func adjStringToVal(s string) (scoreAdjustTyp, bool) {
	for adj := scoreAdjustTyp(1); adj < sentinelScoreAdj; adj <<= 1 {
		if adj.String() == s {
			return adj, true
		}
	}
	return 0, false
}

func parseScoreAdj(val string) error {
	clauses := strings.Split(val, "/")
	if len(clauses) == 0 {
		return fmt.Errorf("no clauses")
	}
	for _, clause := range clauses {
		elems := strings.Split(clause, ":")
		if len(elems) < 2 {
			return fmt.Errorf("clause %q: expected colon", clause)
		}
		if len(elems) != 2 {
			return fmt.Errorf("clause %q has %d elements, wanted 2", clause,
				len(elems))
		}
		adj, ok := adjStringToVal(elems[0])
		if !ok {
			return fmt.Errorf("clause %q: unknown adjustment", clause)
		}
		val, err := strconv.Atoi(elems[1])
		if err != nil {
			return fmt.Errorf("clause %q: malformed value: %v", clause, err)
		}
		adjValues[adj] = val
	}
	return nil
}

func adjValue(x scoreAdjustTyp) int {
	if val, ok := adjValues[x]; ok {
		return val
	} else {
		panic("internal error unregistered adjustment type")
	}
}

var mayMustAdj = [...]struct{ may, must scoreAdjustTyp }{
	{may: passConstToNestedIfAdj, must: passConstToIfAdj},
	{may: passConcreteToNestedItfCallAdj, must: passConcreteToItfCallAdj},
	{may: passFuncToNestedIndCallAdj, must: passFuncToNestedIndCallAdj},
	{may: passInlinableFuncToNestedIndCallAdj, must: passInlinableFuncToIndCallAdj},
}

func isMay(x scoreAdjustTyp) bool {
	return mayToMust(x) != 0
}

func isMust(x scoreAdjustTyp) bool {
	return mustToMay(x) != 0
}

func mayToMust(x scoreAdjustTyp) scoreAdjustTyp {
	for _, v := range mayMustAdj {
		if x == v.may {
			return v.must
		}
	}
	return 0
}

func mustToMay(x scoreAdjustTyp) scoreAdjustTyp {
	for _, v := range mayMustAdj {
		if x == v.must {
			return v.may
		}
	}
	return 0
}

// computeCallSiteScore takes a given call site whose ir node is
// 'call' and callee function is 'callee' and with previously computed
// call site properties 'csflags', then computes a score for the
// callsite that combines the size cost of the callee with heuristics
// based on previously computed argument and function properties,
// then stores the score and the adjustment mask in the appropriate
// fields in 'cs'
func (cs *CallSite) computeCallSiteScore(csa *callSiteAnalyzer, calleeProps *FuncProps) {
	callee := cs.Callee
	csflags := cs.Flags
	call := cs.Call

	// Start with the size-based score for the callee.
	score := int(callee.Inl.Cost)
	var tmask scoreAdjustTyp

	if debugTrace&debugTraceScoring != 0 {
		fmt.Fprintf(os.Stderr, "=-= scoring call to %s at %s , initial=%d\n",
			callee.Sym().Name, fmtFullPos(call.Pos()), score)
	}

	// First some score adjustments to discourage inlining in selected cases.
	if csflags&CallSiteOnPanicPath != 0 {
		score, tmask = adjustScore(panicPathAdj, score, tmask)
	}
	if csflags&CallSiteInInitFunc != 0 {
		score, tmask = adjustScore(initFuncAdj, score, tmask)
	}

	// Then adjustments to encourage inlining in selected cases.
	if csflags&CallSiteInLoop != 0 {
		score, tmask = adjustScore(inLoopAdj, score, tmask)
	}

	// Stop here if no callee props.
	if calleeProps == nil {
		cs.Score, cs.ScoreMask = score, tmask
		return
	}

	// Walk through the actual expressions being passed at the call.
	calleeRecvrParms := callee.Type().RecvParams()
	for idx := range call.Args {
		// ignore blanks
		if calleeRecvrParms[idx].Sym == nil ||
			calleeRecvrParms[idx].Sym.IsBlank() {
			continue
		}
		arg := call.Args[idx]
		pflag := calleeProps.ParamFlags[idx]
		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= arg %d of %d: val %v flags=%s\n",
				idx, len(call.Args), arg, pflag.String())
		}

		if len(cs.ArgProps) == 0 {
			continue
		}
		argProps := cs.ArgProps[idx]

		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= arg %d props %s value %v\n",
				idx, argProps.String(), arg)
		}

		if argProps&ActualExprConstant != 0 {
			if pflag&ParamMayFeedIfOrSwitch != 0 {
				score, tmask = adjustScore(passConstToNestedIfAdj, score, tmask)
			}
			if pflag&ParamFeedsIfOrSwitch != 0 {
				score, tmask = adjustScore(passConstToIfAdj, score, tmask)
			}
		}

		if argProps&ActualExprIsConcreteConvIface != 0 {
			// FIXME: ideally here it would be nice to make a
			// distinction between the inlinable case and the
			// non-inlinable case, but this is hard to do. Example:
			//
			//    type I interface { Tiny() int; Giant() }
			//    type Conc struct { x int }
			//    func (c *Conc) Tiny() int { return 42 }
			//    func (c *Conc) Giant() { <huge amounts of code> }
			//
			//    func passConcToItf(c *Conc) {
			//        makesItfMethodCall(c)
			//    }
			//
			// In the code above, function properties will only tell
			// us that 'makesItfMethodCall' invokes a method on its
			// interface parameter, but we don't know whether it calls
			// "Tiny" or "Giant". If we knew if called "Tiny", then in
			// theory in addition to converting the interface call to
			// a direct call, we could also inline (in which case
			// we'd want to decrease the score even more).
			//
			// One thing we could do (not yet implemented) is iterate
			// through all of the methods of "*Conc" that allow it to
			// satisfy I, and if all are inlinable, then exploit that.
			if pflag&ParamMayFeedInterfaceMethodCall != 0 {
				score, tmask = adjustScore(passConcreteToNestedItfCallAdj, score, tmask)
			}
			if pflag&ParamFeedsInterfaceMethodCall != 0 {
				score, tmask = adjustScore(passConcreteToItfCallAdj, score, tmask)
			}
		}

		if argProps&(ActualExprIsFunc|ActualExprIsInlinableFunc) != 0 {
			mayadj := passFuncToNestedIndCallAdj
			mustadj := passFuncToIndCallAdj
			if argProps&ActualExprIsInlinableFunc != 0 {
				mayadj = passInlinableFuncToNestedIndCallAdj
				mustadj = passInlinableFuncToIndCallAdj
			}
			if pflag&ParamMayFeedIndirectCall != 0 {
				score, tmask = adjustScore(mayadj, score, tmask)
			}
			if pflag&ParamFeedsIndirectCall != 0 {
				score, tmask = adjustScore(mustadj, score, tmask)
			}
		}
	}

	cs.Score, cs.ScoreMask = score, tmask
}

func adjustScore(typ scoreAdjustTyp, score int, mask scoreAdjustTyp) (int, scoreAdjustTyp) {

	if isMust(typ) {
		if mask&typ != 0 {
			return score, mask
		}
		may := mustToMay(typ)
		if mask&may != 0 {
			// promote may to must, so undo may
			score -= adjValue(may)
			mask &^= may
		}
	} else if isMay(typ) {
		must := mayToMust(typ)
		if mask&(must|typ) != 0 {
			return score, mask
		}
	}
	if mask&typ == 0 {
		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= applying adj %d for %s\n",
				adjValue(typ), typ.String())
		}
		score += adjValue(typ)
		mask |= typ
	}
	return score, mask
}

var resultFlagToPositiveAdj map[ResultPropBits]scoreAdjustTyp
var paramFlagToPositiveAdj map[ParamPropBits]scoreAdjustTyp

func setupFlagToAdjMaps() {
	resultFlagToPositiveAdj = map[ResultPropBits]scoreAdjustTyp{
		ResultIsAllocatedMem:     returnFeedsConcreteToInterfaceCallAdj,
		ResultAlwaysSameFunc:     returnFeedsFuncToIndCallAdj,
		ResultAlwaysSameConstant: returnFeedsConstToIfAdj,
	}
	paramFlagToPositiveAdj = map[ParamPropBits]scoreAdjustTyp{
		ParamMayFeedInterfaceMethodCall: passConcreteToNestedItfCallAdj,
		ParamFeedsInterfaceMethodCall:   passConcreteToItfCallAdj,
		ParamMayFeedIndirectCall:        passInlinableFuncToNestedIndCallAdj,
		ParamFeedsIndirectCall:          passInlinableFuncToIndCallAdj,
	}
}

// LargestNegativeScoreAdjustment tries to estimate the largest possible
// negative score adjustment that could be applied to a call of the
// function with the specified props. Example:
//
//	func foo() {                  func bar(x int, p *int) int {
//	   ...                          if x < 0 { *p = x }
//	}                               return 99
//	                              }
//
// Function 'foo' above on the left has no interesting properties,
// thus as a result the most we'll adjust any call to is the value for
// "call in loop". If the calculated cost of the function is 150, and
// the in-loop adjustment is 5 (for example), then there is not much
// point treating it as inlinable. On the other hand "bar" has a param
// property (parameter "x" feeds unmodified to an "if" statement) and
// a return property (always returns same constant) meaning that a
// given call _could_ be rescored down as much as -35 points-- thus if
// the size of "bar" is 100 (for example) then there is at least a
// chance that scoring will enable inlining.
func LargestNegativeScoreAdjustment(fn *ir.Func, props *FuncProps) int {
	if resultFlagToPositiveAdj == nil {
		setupFlagToAdjMaps()
	}
	var tmask scoreAdjustTyp
	score := adjValues[inLoopAdj] // any call can be in a loop
	for _, pf := range props.ParamFlags {
		if adj, ok := paramFlagToPositiveAdj[pf]; ok {
			score, tmask = adjustScore(adj, score, tmask)
		}
	}
	for _, rf := range props.ResultFlags {
		if adj, ok := resultFlagToPositiveAdj[rf]; ok {
			score, tmask = adjustScore(adj, score, tmask)
		}
	}

	if debugTrace&debugTraceScoring != 0 {
		fmt.Fprintf(os.Stderr, "=-= largestScore(%v) is %d\n",
			fn, score)
	}

	return score
}

// LargestPositiveScoreAdjustment tries to estimate the largest possible
// positive score adjustment that could be applied to a given callsite.
// At the moment we don't have very many positive score adjustments, so
// this is just hard-coded, not table-driven.
func LargestPositiveScoreAdjustment(fn *ir.Func) int {
	return adjValues[panicPathAdj] + adjValues[initFuncAdj]
}

// callSiteTab contains entries for each call in the function
// currently being processed by InlineCalls; this variable will either
// be set to 'cstabCache' below (for non-inlinable routines) or to the
// local 'cstab' entry in the fnInlHeur object for inlinable routines.
//
// NOTE: this assumes that inlining operations are happening in a serial,
// single-threaded fashion,f which is true today but probably won't hold
// in the future (for example, we might want to score the callsites
// in multiple functions in parallel); if the inliner evolves in this
// direction we'll need to come up with a different approach here.
var callSiteTab CallSiteTab

// scoreCallsCache caches a call site table and call site list between
// invocations of ScoreCalls so that we can reuse previously allocated
// storage.
var scoreCallsCache scoreCallsCacheType

type scoreCallsCacheType struct {
	tab CallSiteTab
	csl []*CallSite
}

// ScoreCalls assigns numeric scores to each of the callsites in
// function 'fn'; the lower the score, the more helpful we think it
// will be to inline.
//
// Unlike a lot of the other inline heuristics machinery, callsite
// scoring can't be done as part of the CanInline call for a function,
// due to fact that we may be working on a non-trivial SCC. So for
// example with this SCC:
//
//	func foo(x int) {           func bar(x int, f func()) {
//	  if x != 0 {                  f()
//	    bar(x, func(){})           foo(x-1)
//	  }                         }
//	}
//
// We don't want to perform scoring for the 'foo' call in "bar" until
// after foo has been analyzed, but it's conceivable that CanInline
// might visit bar before foo for this SCC.
func ScoreCalls(fn *ir.Func) {
	if len(fn.Body) == 0 {
		return
	}
	enableDebugTraceIfEnv()

	nameFinder := newNameFinder(fn)

	if debugTrace&debugTraceScoring != 0 {
		fmt.Fprintf(os.Stderr, "=-= ScoreCalls(%v)\n", ir.FuncName(fn))
	}

	// If this is an inlinable function, use the precomputed
	// call site table for it. If the function wasn't an inline
	// candidate, collect a callsite table for it now.
	var cstab CallSiteTab
	if funcInlHeur, ok := fpmap[fn]; ok {
		cstab = funcInlHeur.cstab
	} else {
		if len(scoreCallsCache.tab) != 0 {
			panic("missing call to ScoreCallsCleanup")
		}
		if scoreCallsCache.tab == nil {
			scoreCallsCache.tab = make(CallSiteTab)
		}
		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= building cstab for non-inl func %s\n",
				ir.FuncName(fn))
		}
		cstab = computeCallSiteTable(fn, fn.Body, scoreCallsCache.tab, nil, 0,
			nameFinder)
	}

	csa := makeCallSiteAnalyzer(fn)
	const doCallResults = true
	csa.scoreCallsRegion(fn, fn.Body, cstab, doCallResults, nil)

	disableDebugTrace()
}

// scoreCallsRegion assigns numeric scores to each of the callsites in
// region 'region' within function 'fn'. This can be called on
// an entire function, or with 'region' set to a chunk of
// code corresponding to an inlined call.
func (csa *callSiteAnalyzer) scoreCallsRegion(fn *ir.Func, region ir.Nodes, cstab CallSiteTab, doCallResults bool, ic *ir.InlinedCallExpr) {
	if debugTrace&debugTraceScoring != 0 {
		fmt.Fprintf(os.Stderr, "=-= scoreCallsRegion(%v, %s) len(cstab)=%d\n",
			ir.FuncName(fn), region[0].Op().String(), len(cstab))
	}

	// Sort callsites to avoid any surprises with non deterministic
	// map iteration order (this is probably not needed, but here just
	// in case).
	csl := scoreCallsCache.csl[:0]
	for _, cs := range cstab {
		csl = append(csl, cs)
	}
	scoreCallsCache.csl = csl[:0]
	slices.SortFunc(csl, func(a, b *CallSite) int {
		return cmp.Compare(a.ID, b.ID)
	})

	// Score each call site.
	var resultNameTab map[*ir.Name]resultPropAndCS
	for _, cs := range csl {
		var cprops *FuncProps
		fihcprops := false
		desercprops := false
		if funcInlHeur, ok := fpmap[cs.Callee]; ok {
			cprops = funcInlHeur.props
			fihcprops = true
		} else if cs.Callee.Inl != nil {
			cprops = DeserializeFromString(cs.Callee.Inl.Properties)
			desercprops = true
		} else {
			if base.Debug.DumpInlFuncProps != "" {
				fmt.Fprintf(os.Stderr, "=-= *** unable to score call to %s from %s\n", cs.Callee.Sym().Name, fmtFullPos(cs.Call.Pos()))
				panic("should never happen")
			} else {
				continue
			}
		}
		cs.computeCallSiteScore(csa, cprops)

		if doCallResults {
			if debugTrace&debugTraceScoring != 0 {
				fmt.Fprintf(os.Stderr, "=-= examineCallResults at %s: flags=%d score=%d funcInlHeur=%v deser=%v\n", fmtFullPos(cs.Call.Pos()), cs.Flags, cs.Score, fihcprops, desercprops)
			}
			resultNameTab = csa.examineCallResults(cs, resultNameTab)
		}

		if debugTrace&debugTraceScoring != 0 {
			fmt.Fprintf(os.Stderr, "=-= scoring call at %s: flags=%d score=%d funcInlHeur=%v deser=%v\n", fmtFullPos(cs.Call.Pos()), cs.Flags, cs.Score, fihcprops, desercprops)
		}
	}

	if resultNameTab != nil {
		csa.rescoreBasedOnCallResultUses(fn, resultNameTab, cstab)
	}

	disableDebugTrace()

	if ic != nil && callSiteTab != nil {
		// Integrate the calls from this cstab into the table for the caller.
		if err := callSiteTab.merge(cstab); err != nil {
			base.FatalfAt(ic.Pos(), "%v", err)
		}
	} else {
		callSiteTab = cstab
	}
}

// ScoreCallsCleanup resets the state of the callsite cache
// once ScoreCalls is done with a function.
func ScoreCallsCleanup() {
	if base.Debug.DumpInlCallSiteScores != 0 {
		if allCallSites == nil {
			allCallSites = make(CallSiteTab)
		}
		for call, cs := range callSiteTab {
			allCallSites[call] = cs
		}
	}
	clear(scoreCallsCache.tab)
}

// GetCallSiteScore returns the previously calculated score for call
// within fn.
func GetCallSiteScore(fn *ir.Func, call *ir.CallExpr) (int, bool) {
	if funcInlHeur, ok := fpmap[fn]; ok {
		if cs, ok := funcInlHeur.cstab[call]; ok {
			return cs.Score, true
		}
	}
	if cs, ok := callSiteTab[call]; ok {
		return cs.Score, true
	}
	return 0, false
}

// BudgetExpansion returns the amount to relax/expand the base
// inlining budget when the new inliner is turned on; the inliner
// will add the returned value to the hairiness budget.
//
// Background: with the new inliner, the score for a given callsite
// can be adjusted down by some amount due to heuristics, however we
// won't know whether this is going to happen until much later after
// the CanInline call. This function returns the amount to relax the
// budget initially (to allow for a large score adjustment); later on
// in RevisitInlinability we'll look at each individual function to
// demote it if needed.
func BudgetExpansion(maxBudget int32) int32 {
	if base.Debug.InlBudgetSlack != 0 {
		return int32(base.Debug.InlBudgetSlack)
	}
	// In the default case, return maxBudget, which will effectively
	// double the budget from 80 to 160; this should be good enough
	// for most cases.
	return maxBudget
}

var allCallSites CallSiteTab

// DumpInlCallSiteScores is invoked by the inliner if the debug flag
// "-d=dumpinlcallsitescores" is set; it dumps out a human-readable
// summary of all (potentially) inlinable callsites in the package,
// along with info on call site scoring and the adjustments made to a
// given score. Here profile is the PGO profile in use (may be
// nil), budgetCallback is a callback that can be invoked to find out
// the original pre-adjustment hairiness limit for the function, and
// inlineHotMaxBudget is the constant of the same name used in the
// inliner. Sample output lines:
//
// Score  Adjustment  Status  Callee  CallerPos ScoreFlags
// 115    40          DEMOTED cmd/compile/internal/abi.(*ABIParamAssignment).Offset     expand_calls.go:1679:14|6       panicPathAdj
// 76     -5n         PROMOTED runtime.persistentalloc   mcheckmark.go:48:45|3   inLoopAdj
// 201    0           --- PGO  unicode.DecodeRuneInString        utf8.go:312:30|1
// 7      -5          --- PGO  internal/abi.Name.DataChecked     type.go:625:22|0        inLoopAdj
//
// In the dump above, "Score" is the final score calculated for the
// callsite, "Adjustment" is the amount added to or subtracted from
// the original hairiness estimate to form the score. "Status" shows
// whether anything changed with the site -- did the adjustment bump
// it down just below the threshold ("PROMOTED") or instead bump it
// above the threshold ("DEMOTED"); this will be blank ("---") if no
// threshold was crossed as a result of the heuristics. Note that
// "Status" also shows whether PGO was involved. "Callee" is the name
// of the function called, "CallerPos" is the position of the
// callsite, and "ScoreFlags" is a digest of the specific properties
// we used to make adjustments to callsite score via heuristics.
func DumpInlCallSiteScores(profile *pgoir.Profile, budgetCallback func(fn *ir.Func, profile *pgoir.Profile) (int32, bool)) {

	var indirectlyDueToPromotion func(cs *CallSite) bool
	indirectlyDueToPromotion = func(cs *CallSite) bool {
		bud, _ := budgetCallback(cs.Callee, profile)
		hairyval := cs.Callee.Inl.Cost
		score := int32(cs.Score)
		if hairyval > bud && score <= bud {
			return true
		}
		if cs.parent != nil {
			return indirectlyDueToPromotion(cs.parent)
		}
		return false
	}

	genstatus := func(cs *CallSite) string {
		hairyval := cs.Callee.Inl.Cost
		bud, isPGO := budgetCallback(cs.Callee, profile)
		score := int32(cs.Score)
		st := "---"
		expinl := false
		switch {
		case hairyval <= bud && score <= bud:
			// "Normal" inlined case: hairy val sufficiently low that
			// it would have been inlined anyway without heuristics.
			expinl = true
		case hairyval > bud && score > bud:
			// "Normal" not inlined case: hairy val sufficiently high
			// and scoring didn't lower it.
		case hairyval > bud && score <= bud:
			// Promoted: we would not have inlined it before, but
			// after score adjustment we decided to inline.
			st = "PROMOTED"
			expinl = true
		case hairyval <= bud && score > bud:
			// Demoted: we would have inlined it before, but after
			// score adjustment we decided not to inline.
			st = "DEMOTED"
		}
		inlined := cs.aux&csAuxInlined != 0
		indprom := false
		if cs.parent != nil {
			indprom = indirectlyDueToPromotion(cs.parent)
		}
		if inlined && indprom {
			st += "|INDPROM"
		}
		if inlined && !expinl {
			st += "|[NI?]"
		} else if !inlined && expinl {
			st += "|[IN?]"
		}
		if isPGO {
			st += "|PGO"
		}
		return st
	}

	if base.Debug.DumpInlCallSiteScores != 0 {
		var sl []*CallSite
		for _, cs := range allCallSites {
			sl = append(sl, cs)
		}
		slices.SortFunc(sl, func(a, b *CallSite) int {
			if a.Score != b.Score {
				return cmp.Compare(a.Score, b.Score)
			}
			fni := ir.PkgFuncName(a.Callee)
			fnj := ir.PkgFuncName(b.Callee)
			if fni != fnj {
				return cmp.Compare(fni, fnj)
			}
			ecsi := EncodeCallSiteKey(a)
			ecsj := EncodeCallSiteKey(b)
			return cmp.Compare(ecsi, ecsj)
		})

		mkname := func(fn *ir.Func) string {
			var n string
			if fn == nil || fn.Nname == nil {
				return "<nil>"
			}
			if fn.Sym().Pkg == types.LocalPkg {
				n = "·" + fn.Sym().Name
			} else {
				n = ir.PkgFuncName(fn)
			}
			// don't try to print super-long names
			if len(n) <= 64 {
				return n
			}
			return n[:32] + "..." + n[len(n)-32:len(n)]
		}

		if len(sl) != 0 {
			fmt.Fprintf(os.Stdout, "# scores for package %s\n", types.LocalPkg.Path)
			fmt.Fprintf(os.Stdout, "# Score  Adjustment  Status  Callee  CallerPos Flags ScoreFlags\n")
		}
		for _, cs := range sl {
			hairyval := cs.Callee.Inl.Cost
			adj := int32(cs.Score) - hairyval
			nm := mkname(cs.Callee)
			ecc := EncodeCallSiteKey(cs)
			fmt.Fprintf(os.Stdout, "%d  %d\t%s\t%s\t%s\t%s\n",
				cs.Score, adj, genstatus(cs),
				nm, ecc,
				cs.ScoreMask.String())
		}
	}
}
```