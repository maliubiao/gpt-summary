Response:
Let's break down the thought process for analyzing the Go code snippet.

**1. Initial Understanding - What is the Goal?**

The first thing I noticed was the package name: `devirtualize`. Combined with the function name `ProfileGuided`, this strongly suggests the code is about optimizing indirect function calls by converting them into direct calls where possible. The comments further confirm this, explicitly mentioning "call devirtualization of indirect calls based on profile information."

**2. Key Data Structures and Concepts:**

* **`CallStat`:**  This struct is clearly for logging and debugging. It captures information about call sites, including whether they are direct or indirect, interface calls, weights, and devirtualization status. It's useful for understanding the *what* and *why* of devirtualization decisions.

* **Profile Information (`p *pgoir.Profile`)**: The function takes a profile as input, indicating that it's using Profile-Guided Optimization (PGO). This means the compiler is using runtime performance data to make optimization decisions.

* **Indirect Calls (Interface and Function Value):** The comments and code examples clearly differentiate between interface method calls and calls through function variables. This distinction is crucial because the devirtualization techniques are different for each.

* **Devirtualization Logic:** The core of the code lies within the `ProfileGuided` function and its helper functions (`maybeDevirtualizeInterfaceCall`, `maybeDevirtualizeFunctionCall`, `rewriteInterfaceCall`, `rewriteFunctionCall`). These functions determine *if* and *how* to perform devirtualization.

**3. Function-by-Function Analysis (High-Level):**

* **`ProfileGuided`:**  The main entry point. It iterates through the function's code, identifies indirect calls, and attempts devirtualization. It also handles debug logging. The `edit` function within is a standard way to traverse and modify the Go AST.

* **`maybeDevirtualizeInterfaceCall` and `maybeDevirtualizeFunctionCall`:** These functions decide *whether* to devirtualize a specific call site based on factors like debug flags, the existence of a hot callee (most frequently called function), and whether inlining is likely.

* **`rewriteInterfaceCall` and `rewriteFunctionCall`:** These functions implement the actual *how* of devirtualization. They generate the new Go code that includes a type assertion or function pointer comparison to conditionally call the concrete implementation.

* **`shouldPGODevirt`:** A helper function to determine if a function is a good candidate for devirtualization based on its inlining potential.

* **`constructCallStat`:**  Populates the `CallStat` struct for logging purposes.

* **`copyInputs`:**  A helper function to ensure that the arguments to the original and devirtualized calls are evaluated only once, preventing potential side-effect issues.

* **`retTemps`:**  Creates temporary variables to store the return values of the call.

* **`condCall`:**  Generates the `if-else` block that conditionally executes either the original indirect call or the direct, devirtualized call.

* **Helper Functions for finding hot callees (`findHotConcreteCallee`, `findHotConcreteInterfaceCallee`, `findHotConcreteFunctionCallee`):** These functions analyze the PGO profile to identify the most frequently called concrete implementation for a given indirect call site.

* **Helper Functions for type information (`methodRecvType`, `interfaceCallRecvTypeAndMethod`):** Extract necessary type information for making devirtualization decisions.

**4. Inferring the Go Functionality:**

Based on the code and comments, the core functionality is **Profile-Guided Devirtualization of Indirect Function Calls**. This is a specific compiler optimization technique.

**5. Code Example Construction:**

To illustrate the functionality, I needed examples for both interface calls and function value calls. The examples in the code comments were a great starting point. I then expanded them to be complete, runnable Go code snippets. I focused on showing the transformation before and after devirtualization.

**6. Input and Output Reasoning:**

For the code examples, the "input" is the original Go code, and the "output" is the transformed Go code after devirtualization. I explicitly showed this transformation in the examples. For `findHotConcreteCallee`, I reasoned about what kind of PGO profile data would lead to a specific function being identified as the hottest callee.

**7. Command-Line Arguments:**

I scanned the code for references to `base.Debug` and `base.Flag`. This is the standard way Go compiler flags are accessed. I identified flags related to PGO debugging (`PGODebug`) and controlling the level of devirtualization (`PGODevirtualize`). I also noted the use of `base.PGOHash` which suggests a mechanism for selectively applying devirtualization.

**8. Common Mistakes:**

I thought about potential pitfalls for developers working with or relying on PGO devirtualization. The key mistake is expecting devirtualization to happen in all cases. Factors like the lack of profile data, cold call sites, inlining limitations, and PGO hash mismatches can prevent devirtualization. I crafted an example to demonstrate a scenario where devirtualization *wouldn't* occur.

**Self-Correction/Refinement During the Process:**

* **Initially, I might have focused too much on the specific code details.**  I had to step back and think about the overall purpose and the high-level transformations being performed.
* **I made sure to distinguish between the *decision* to devirtualize and the *process* of rewriting the code.** This is reflected in the separation of `maybeDevirtualize...` and `rewrite...` functions.
* **I double-checked the comments to ensure my understanding aligned with the author's intent.** The comments are quite helpful in this case.
* **I iteratively refined the code examples to make them clearer and more illustrative.** I considered different scenarios and edge cases.

By following this structured approach, I could systematically analyze the Go code snippet and provide a comprehensive explanation of its functionality, including illustrative examples, reasoning about inputs and outputs, command-line arguments, and potential pitfalls.
这段代码是 Go 编译器中与 **Profile-Guided Optimization (PGO)** 相关的 **devirtualization** 功能的实现。 它的主要功能是：

**1. 基于性能剖析信息，将间接调用转换为直接调用 (Profile-Guided Devirtualization):**

   - 它分析 PGO 性能剖析数据 (`p *pgoir.Profile`)，识别出在运行时最常被调用的具体函数。
   - 对于接口调用 (`ir.OCALLINTER`) 或函数值调用 (`ir.OCALLFUNC`)，如果能确定最常调用的具体目标函数，则会将间接调用点转换成一个条件语句，尝试直接调用该目标函数。
   - 这种转换的主要目的是为了 **启用内联优化**。直接调用更容易被内联，可以提升性能。

**2. 针对接口调用的条件性去虚化 (Conditional Devirtualization of Interface Calls):**

   - 对于接口调用 `i.Foo()`，它会生成类似下面的代码：
     ```go
     func foo(i Iface) {
         if c, ok := i.(Concrete); ok { // 类型断言
             c.Foo() // 直接调用 Concrete.Foo
         } else {
             i.Foo() // 原始的接口调用
         }
     }
     ```
   - 其中 `Concrete` 是根据 PGO 数据推断出的最常被调用的 `Iface` 的具体类型。

**3. 针对函数值调用的条件性去虚化 (Conditional Devirtualization of Function Value Calls):**

   - 对于函数值调用 `fn()`，它会生成类似下面的代码：
     ```go
     func foo(fn func()) {
         if internal/abi.FuncPCABIInternal(fn) == internal/abi.FuncPCABIInternal(Concrete) { // 比较函数指针
             Concrete() // 直接调用 Concrete 函数
         } else {
             fn() // 原始的函数值调用
         }
     }
     ```
   - 其中 `Concrete` 是根据 PGO 数据推断出的最常被赋值给 `fn` 的具体函数。

**4. Debug 日志记录 (Debug Logging):**

   -  通过 `base.Debug.PGODebug` 控制不同级别的 debug 信息输出。
   -  `CallStat` 结构体用于记录每个调用点的统计信息，包括调用者、被调用者、是否直接调用、接口调用、权重等。这些信息可以用于调试和性能分析。

**Go 代码举例说明:**

**假设的输入：**

有一个接口 `Iface` 和两个实现了该接口的类型 `ConcreteA` 和 `ConcreteB`。  PGO 数据显示，在 `foo` 函数中调用 `i.Bar()` 时，90% 的情况下 `i` 的实际类型是 `ConcreteA`。

```go
package main

type Iface interface {
	Bar()
}

type ConcreteA struct{}
func (ConcreteA) Bar() { println("ConcreteA.Bar") }

type ConcreteB struct{}
func (ConcreteB) Bar() { println("ConcreteB.Bar") }

func foo(i Iface) {
	i.Bar()
}

func main() {
	var a Iface = ConcreteA{}
	foo(a)
	var b Iface = ConcreteB{}
	// 假设在性能剖析中，对 foo(b) 的调用次数远少于 foo(a)
	// ...
	foo(b)
}
```

**`go/src/cmd/compile/internal/devirtualize/pgo.go` 处理后的代码（近似）：**

```go
package main

import "reflect" // 为了类型断言

type Iface interface {
	Bar()
}

type ConcreteA struct{}
func (ConcreteA) Bar() { println("ConcreteA.Bar") }

type ConcreteB struct{}
func (ConcreteB) Bar() { println("ConcreteB.Bar") }

func foo(i Iface) {
	if ca, ok := i.(ConcreteA); ok { // 基于 PGO 数据，尝试断言为 ConcreteA
		ca.Bar()
	} else {
		i.Bar()
	}
}

func main() {
	var a Iface = ConcreteA{}
	foo(a)
	var b Iface = ConcreteB{}
	foo(b)
}
```

**假设的输入与输出 (函数值调用):**

假设有一个函数类型的变量 `op`，并且 PGO 数据显示，在 `calculate` 函数中调用 `op()` 时，80% 的情况下 `op` 指向 `add` 函数。

```go
package main

func add(a, b int) int {
	return a + b
}

func multiply(a, b int) int {
	return a * b
}

func calculate(op func(int, int) int, x, y int) int {
	return op(x, y)
}

func main() {
	result := calculate(add, 5, 3)
	println(result)
	// ... 假设性能剖析显示 calculate(add, ...) 调用更多
	result = calculate(multiply, 5, 3)
	println(result)
}
```

**`go/src/cmd/compile/internal/devirtualize/pgo.go` 处理后的代码（近似）：**

```go
package main

import "internal/abi" // 用于比较函数指针

func add(a, b int) int {
	return a + b
}

func multiply(a, b int) int {
	return a * b
}

func calculate(op func(int, int) int, x, y int) int {
	if abi.FuncPCABIInternal(reflect.ValueOf(op).Pointer()) == abi.FuncPCABIInternal(reflect.ValueOf(add).Pointer()) {
		return add(x, y)
	} else {
		return op(x, y)
	}
}

func main() {
	result := calculate(add, 5, 3)
	println(result)
	result = calculate(multiply, 5, 3)
	println(result)
}
```

**命令行参数的具体处理:**

这段代码本身不直接处理命令行参数。但是，它使用了全局的 `base.Debug` 和 `base.Flag` 对象来获取编译器的 debug 设置和 flag 值。

- **`base.Debug.PGODebug`:**  控制 PGO 相关的 debug 信息输出级别。
    - `PGODebug >= 3`: 输出关于每个调用的详细 JSON 统计信息。
    - `PGODebug >= 2`: 输出关于 PGO 去虚化的决策过程的详细信息。
- **`base.Debug.PGODevirtualize`:** 控制 PGO 去虚化的激进程度。
    - `PGODevirtualize < 1`:  禁用接口调用的去虚化。
    - `PGODevirtualize < 2`:  禁用函数值调用的去虚化。
- **`base.Flag.LowerM`:**  如果大于 0，会在控制台输出 PGO 去虚化的相关信息。
- **`base.PGOHash`:** 用于基于位置信息进行选择性的 PGO 优化，可以控制哪些调用点进行去虚化。

这些 flag 通常通过 `go build` 或 `go tool compile` 命令的 `-gcflags` 参数传递，例如：

```bash
go build -gcflags="-d=pgo=3" mypackage.go
go build -gcflags="-d=pgodevirtualize=1" mypackage.go
go build -gcflags="-m=2" mypackage.go # 这会间接触发 LowerM 的输出
```

**使用者易犯错的点 (假设的使用场景):**

1. **没有提供 PGO profile 数据:** 如果没有提供性能剖析数据，编译器无法判断哪个具体类型或函数被调用的频率最高，因此无法进行有效的去虚化。使用者需要先运行程序生成 profile 数据，然后在编译时使用 `-pgo` 参数指定 profile 文件。

2. **Profile 数据不具有代表性:**  如果生成的 profile 数据覆盖的场景不足，或者测试用例与实际生产环境差异较大，那么基于这些数据进行的去虚化可能不会带来预期的性能提升，甚至可能因为错误的判断导致性能下降。

3. **过度依赖 PGO 进行性能优化:** PGO 是一种强大的优化手段，但不应该作为唯一的性能优化方法。使用者应该首先关注代码本身的效率和算法的优化。

4. **忽略 `-gcflags` 参数:**  使用者可能不知道可以通过 `-gcflags` 来调整 PGO 相关的 debug 和优化选项，导致无法获取有用的 debug 信息或调整去虚化的行为。

5. **误解去虚化的效果:**  使用者可能认为只要开启了 PGO，所有的间接调用都会被去虚化。但实际上，去虚化是基于统计的，并且受到多种因素的影响，并非所有间接调用都适合或能够被去虚化。例如，如果多个不同的具体类型在接口调用点被频繁调用，那么去虚化的收益可能会降低，甚至不进行去虚化。

总而言之，这段代码实现了 Go 编译器中基于性能剖析信息的间接调用去虚化功能，通过将间接调用转换为条件性的直接调用，为后续的内联优化提供了机会，从而提升程序的运行性能。 理解其工作原理和相关的命令行参数对于有效地利用 PGO 进行性能优化至关重要。

### 提示词
```
这是路径为go/src/cmd/compile/internal/devirtualize/pgo.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package devirtualize

import (
	"cmd/compile/internal/base"
	"cmd/compile/internal/inline"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/logopt"
	"cmd/compile/internal/pgoir"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/obj"
	"cmd/internal/src"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// CallStat summarizes a single call site.
//
// This is used only for debug logging.
type CallStat struct {
	Pkg string // base.Ctxt.Pkgpath
	Pos string // file:line:col of call.

	Caller string // Linker symbol name of calling function.

	// Direct or indirect call.
	Direct bool

	// For indirect calls, interface call or other indirect function call.
	Interface bool

	// Total edge weight from this call site.
	Weight int64

	// Hottest callee from this call site, regardless of type
	// compatibility.
	Hottest       string
	HottestWeight int64

	// Devirtualized callee if != "".
	//
	// Note that this may be different than Hottest because we apply
	// type-check restrictions, which helps distinguish multiple calls on
	// the same line.
	Devirtualized       string
	DevirtualizedWeight int64
}

// ProfileGuided performs call devirtualization of indirect calls based on
// profile information.
//
// Specifically, it performs conditional devirtualization of interface calls or
// function value calls for the hottest callee.
//
// That is, for interface calls it performs a transformation like:
//
//	type Iface interface {
//		Foo()
//	}
//
//	type Concrete struct{}
//
//	func (Concrete) Foo() {}
//
//	func foo(i Iface) {
//		i.Foo()
//	}
//
// to:
//
//	func foo(i Iface) {
//		if c, ok := i.(Concrete); ok {
//			c.Foo()
//		} else {
//			i.Foo()
//		}
//	}
//
// For function value calls it performs a transformation like:
//
//	func Concrete() {}
//
//	func foo(fn func()) {
//		fn()
//	}
//
// to:
//
//	func foo(fn func()) {
//		if internal/abi.FuncPCABIInternal(fn) == internal/abi.FuncPCABIInternal(Concrete) {
//			Concrete()
//		} else {
//			fn()
//		}
//	}
//
// The primary benefit of this transformation is enabling inlining of the
// direct call.
func ProfileGuided(fn *ir.Func, p *pgoir.Profile) {
	ir.CurFunc = fn

	name := ir.LinkFuncName(fn)

	var jsonW *json.Encoder
	if base.Debug.PGODebug >= 3 {
		jsonW = json.NewEncoder(os.Stdout)
	}

	var edit func(n ir.Node) ir.Node
	edit = func(n ir.Node) ir.Node {
		if n == nil {
			return n
		}

		ir.EditChildren(n, edit)

		call, ok := n.(*ir.CallExpr)
		if !ok {
			return n
		}

		var stat *CallStat
		if base.Debug.PGODebug >= 3 {
			// Statistics about every single call. Handy for external data analysis.
			//
			// TODO(prattmic): Log via logopt?
			stat = constructCallStat(p, fn, name, call)
			if stat != nil {
				defer func() {
					jsonW.Encode(&stat)
				}()
			}
		}

		op := call.Op()
		if op != ir.OCALLFUNC && op != ir.OCALLINTER {
			return n
		}

		if base.Debug.PGODebug >= 2 {
			fmt.Printf("%v: PGO devirtualize considering call %v\n", ir.Line(call), call)
		}

		if call.GoDefer {
			if base.Debug.PGODebug >= 2 {
				fmt.Printf("%v: can't PGO devirtualize go/defer call %v\n", ir.Line(call), call)
			}
			return n
		}

		var newNode ir.Node
		var callee *ir.Func
		var weight int64
		switch op {
		case ir.OCALLFUNC:
			newNode, callee, weight = maybeDevirtualizeFunctionCall(p, fn, call)
		case ir.OCALLINTER:
			newNode, callee, weight = maybeDevirtualizeInterfaceCall(p, fn, call)
		default:
			panic("unreachable")
		}

		if newNode == nil {
			return n
		}

		if stat != nil {
			stat.Devirtualized = ir.LinkFuncName(callee)
			stat.DevirtualizedWeight = weight
		}

		return newNode
	}

	ir.EditChildren(fn, edit)
}

// Devirtualize interface call if possible and eligible. Returns the new
// ir.Node if call was devirtualized, and if so also the callee and weight of
// the devirtualized edge.
func maybeDevirtualizeInterfaceCall(p *pgoir.Profile, fn *ir.Func, call *ir.CallExpr) (ir.Node, *ir.Func, int64) {
	if base.Debug.PGODevirtualize < 1 {
		return nil, nil, 0
	}

	// Bail if we do not have a hot callee.
	callee, weight := findHotConcreteInterfaceCallee(p, fn, call)
	if callee == nil {
		return nil, nil, 0
	}
	// Bail if we do not have a Type node for the hot callee.
	ctyp := methodRecvType(callee)
	if ctyp == nil {
		return nil, nil, 0
	}
	// Bail if we know for sure it won't inline.
	if !shouldPGODevirt(callee) {
		return nil, nil, 0
	}
	// Bail if de-selected by PGO Hash.
	if !base.PGOHash.MatchPosWithInfo(call.Pos(), "devirt", nil) {
		return nil, nil, 0
	}

	return rewriteInterfaceCall(call, fn, callee, ctyp), callee, weight
}

// Devirtualize an indirect function call if possible and eligible. Returns the new
// ir.Node if call was devirtualized, and if so also the callee and weight of
// the devirtualized edge.
func maybeDevirtualizeFunctionCall(p *pgoir.Profile, fn *ir.Func, call *ir.CallExpr) (ir.Node, *ir.Func, int64) {
	if base.Debug.PGODevirtualize < 2 {
		return nil, nil, 0
	}

	// Bail if this is a direct call; no devirtualization necessary.
	callee := pgoir.DirectCallee(call.Fun)
	if callee != nil {
		return nil, nil, 0
	}

	// Bail if we do not have a hot callee.
	callee, weight := findHotConcreteFunctionCallee(p, fn, call)
	if callee == nil {
		return nil, nil, 0
	}

	// TODO(go.dev/issue/61577): Closures need the closure context passed
	// via the context register. That requires extra plumbing that we
	// haven't done yet.
	if callee.OClosure != nil {
		if base.Debug.PGODebug >= 3 {
			fmt.Printf("callee %s is a closure, skipping\n", ir.FuncName(callee))
		}
		return nil, nil, 0
	}
	// runtime.memhash_varlen does not look like a closure, but it uses
	// internal/runtime/sys.GetClosurePtr to access data encoded by
	// callers, which are generated by
	// cmd/compile/internal/reflectdata.genhash.
	if callee.Sym().Pkg.Path == "runtime" && callee.Sym().Name == "memhash_varlen" {
		if base.Debug.PGODebug >= 3 {
			fmt.Printf("callee %s is a closure (runtime.memhash_varlen), skipping\n", ir.FuncName(callee))
		}
		return nil, nil, 0
	}
	// TODO(prattmic): We don't properly handle methods as callees in two
	// different dimensions:
	//
	// 1. Method expressions. e.g.,
	//
	//      var fn func(*os.File, []byte) (int, error) = (*os.File).Read
	//
	// In this case, typ will report *os.File as the receiver while
	// ctyp reports it as the first argument. types.Identical ignores
	// receiver parameters, so it treats these as different, even though
	// they are still call compatible.
	//
	// 2. Method values. e.g.,
	//
	//      var f *os.File
	//      var fn func([]byte) (int, error) = f.Read
	//
	// types.Identical will treat these as compatible (since receiver
	// parameters are ignored). However, in this case, we do not call
	// (*os.File).Read directly. Instead, f is stored in closure context
	// and we call the wrapper (*os.File).Read-fm. However, runtime/pprof
	// hides wrappers from profiles, making it appear that there is a call
	// directly to the method. We could recognize this pattern return the
	// wrapper rather than the method.
	//
	// N.B. perf profiles will report wrapper symbols directly, so
	// ideally we should support direct wrapper references as well.
	if callee.Type().Recv() != nil {
		if base.Debug.PGODebug >= 3 {
			fmt.Printf("callee %s is a method, skipping\n", ir.FuncName(callee))
		}
		return nil, nil, 0
	}

	// Bail if we know for sure it won't inline.
	if !shouldPGODevirt(callee) {
		return nil, nil, 0
	}
	// Bail if de-selected by PGO Hash.
	if !base.PGOHash.MatchPosWithInfo(call.Pos(), "devirt", nil) {
		return nil, nil, 0
	}

	return rewriteFunctionCall(call, fn, callee), callee, weight
}

// shouldPGODevirt checks if we should perform PGO devirtualization to the
// target function.
//
// PGO devirtualization is most valuable when the callee is inlined, so if it
// won't inline we can skip devirtualizing.
func shouldPGODevirt(fn *ir.Func) bool {
	var reason string
	if base.Flag.LowerM > 1 || logopt.Enabled() {
		defer func() {
			if reason != "" {
				if base.Flag.LowerM > 1 {
					fmt.Printf("%v: should not PGO devirtualize %v: %s\n", ir.Line(fn), ir.FuncName(fn), reason)
				}
				if logopt.Enabled() {
					logopt.LogOpt(fn.Pos(), ": should not PGO devirtualize function", "pgoir-devirtualize", ir.FuncName(fn), reason)
				}
			}
		}()
	}

	reason = inline.InlineImpossible(fn)
	if reason != "" {
		return false
	}

	// TODO(prattmic): checking only InlineImpossible is very conservative,
	// primarily excluding only functions with pragmas. We probably want to
	// move in either direction. Either:
	//
	// 1. Don't even bother to check InlineImpossible, as it affects so few
	// functions.
	//
	// 2. Or consider the function body (notably cost) to better determine
	// if the function will actually inline.

	return true
}

// constructCallStat builds an initial CallStat describing this call, for
// logging. If the call is devirtualized, the devirtualization fields should be
// updated.
func constructCallStat(p *pgoir.Profile, fn *ir.Func, name string, call *ir.CallExpr) *CallStat {
	switch call.Op() {
	case ir.OCALLFUNC, ir.OCALLINTER, ir.OCALLMETH:
	default:
		// We don't care about logging builtin functions.
		return nil
	}

	stat := CallStat{
		Pkg:    base.Ctxt.Pkgpath,
		Pos:    ir.Line(call),
		Caller: name,
	}

	offset := pgoir.NodeLineOffset(call, fn)

	hotter := func(e *pgoir.IREdge) bool {
		if stat.Hottest == "" {
			return true
		}
		if e.Weight != stat.HottestWeight {
			return e.Weight > stat.HottestWeight
		}
		// If weight is the same, arbitrarily sort lexicographally, as
		// findHotConcreteCallee does.
		return e.Dst.Name() < stat.Hottest
	}

	callerNode := p.WeightedCG.IRNodes[name]
	if callerNode == nil {
		return nil
	}

	// Sum of all edges from this callsite, regardless of callee.
	// For direct calls, this should be the same as the single edge
	// weight (except for multiple calls on one line, which we
	// can't distinguish).
	for _, edge := range callerNode.OutEdges {
		if edge.CallSiteOffset != offset {
			continue
		}
		stat.Weight += edge.Weight
		if hotter(edge) {
			stat.HottestWeight = edge.Weight
			stat.Hottest = edge.Dst.Name()
		}
	}

	switch call.Op() {
	case ir.OCALLFUNC:
		stat.Interface = false

		callee := pgoir.DirectCallee(call.Fun)
		if callee != nil {
			stat.Direct = true
			if stat.Hottest == "" {
				stat.Hottest = ir.LinkFuncName(callee)
			}
		} else {
			stat.Direct = false
		}
	case ir.OCALLINTER:
		stat.Direct = false
		stat.Interface = true
	case ir.OCALLMETH:
		base.FatalfAt(call.Pos(), "OCALLMETH missed by typecheck")
	}

	return &stat
}

// copyInputs copies the inputs to a call: the receiver (for interface calls)
// or function value (for function value calls) and the arguments. These
// expressions are evaluated once and assigned to temporaries.
//
// The assignment statement is added to init and the copied receiver/fn
// expression and copied arguments expressions are returned.
func copyInputs(curfn *ir.Func, pos src.XPos, recvOrFn ir.Node, args []ir.Node, init *ir.Nodes) (ir.Node, []ir.Node) {
	// Evaluate receiver/fn and argument expressions. The receiver/fn is
	// used twice but we don't want to cause side effects twice. The
	// arguments are used in two different calls and we can't trivially
	// copy them.
	//
	// recvOrFn must be first in the assignment list as its side effects
	// must be ordered before argument side effects.
	var lhs, rhs []ir.Node
	newRecvOrFn := typecheck.TempAt(pos, curfn, recvOrFn.Type())
	lhs = append(lhs, newRecvOrFn)
	rhs = append(rhs, recvOrFn)

	for _, arg := range args {
		argvar := typecheck.TempAt(pos, curfn, arg.Type())

		lhs = append(lhs, argvar)
		rhs = append(rhs, arg)
	}

	asList := ir.NewAssignListStmt(pos, ir.OAS2, lhs, rhs)
	init.Append(typecheck.Stmt(asList))

	return newRecvOrFn, lhs[1:]
}

// retTemps returns a slice of temporaries to be used for storing result values from call.
func retTemps(curfn *ir.Func, pos src.XPos, call *ir.CallExpr) []ir.Node {
	sig := call.Fun.Type()
	var retvars []ir.Node
	for _, ret := range sig.Results() {
		retvars = append(retvars, typecheck.TempAt(pos, curfn, ret.Type))
	}
	return retvars
}

// condCall returns an ir.InlinedCallExpr that performs a call to thenCall if
// cond is true and elseCall if cond is false. The return variables of the
// InlinedCallExpr evaluate to the return values from the call.
func condCall(curfn *ir.Func, pos src.XPos, cond ir.Node, thenCall, elseCall *ir.CallExpr, init ir.Nodes) *ir.InlinedCallExpr {
	// Doesn't matter whether we use thenCall or elseCall, they must have
	// the same return types.
	retvars := retTemps(curfn, pos, thenCall)

	var thenBlock, elseBlock ir.Nodes
	if len(retvars) == 0 {
		thenBlock.Append(thenCall)
		elseBlock.Append(elseCall)
	} else {
		// Copy slice so edits in one location don't affect another.
		thenRet := append([]ir.Node(nil), retvars...)
		thenAsList := ir.NewAssignListStmt(pos, ir.OAS2, thenRet, []ir.Node{thenCall})
		thenBlock.Append(typecheck.Stmt(thenAsList))

		elseRet := append([]ir.Node(nil), retvars...)
		elseAsList := ir.NewAssignListStmt(pos, ir.OAS2, elseRet, []ir.Node{elseCall})
		elseBlock.Append(typecheck.Stmt(elseAsList))
	}

	nif := ir.NewIfStmt(pos, cond, thenBlock, elseBlock)
	nif.SetInit(init)
	nif.Likely = true

	body := []ir.Node{typecheck.Stmt(nif)}

	// This isn't really an inlined call of course, but InlinedCallExpr
	// makes handling reassignment of return values easier.
	res := ir.NewInlinedCallExpr(pos, body, retvars)
	res.SetType(thenCall.Type())
	res.SetTypecheck(1)
	return res
}

// rewriteInterfaceCall devirtualizes the given interface call using a direct
// method call to concretetyp.
func rewriteInterfaceCall(call *ir.CallExpr, curfn, callee *ir.Func, concretetyp *types.Type) ir.Node {
	if base.Flag.LowerM != 0 {
		fmt.Printf("%v: PGO devirtualizing interface call %v to %v\n", ir.Line(call), call.Fun, callee)
	}

	// We generate an OINCALL of:
	//
	// var recv Iface
	//
	// var arg1 A1
	// var argN AN
	//
	// var ret1 R1
	// var retN RN
	//
	// recv, arg1, argN = recv expr, arg1 expr, argN expr
	//
	// t, ok := recv.(Concrete)
	// if ok {
	//   ret1, retN = t.Method(arg1, ... argN)
	// } else {
	//   ret1, retN = recv.Method(arg1, ... argN)
	// }
	//
	// OINCALL retvars: ret1, ... retN
	//
	// This isn't really an inlined call of course, but InlinedCallExpr
	// makes handling reassignment of return values easier.
	//
	// TODO(prattmic): This increases the size of the AST in the caller,
	// making it less like to inline. We may want to compensate for this
	// somehow.

	sel := call.Fun.(*ir.SelectorExpr)
	method := sel.Sel
	pos := call.Pos()
	init := ir.TakeInit(call)

	recv, args := copyInputs(curfn, pos, sel.X, call.Args.Take(), &init)

	// Copy slice so edits in one location don't affect another.
	argvars := append([]ir.Node(nil), args...)
	call.Args = argvars

	tmpnode := typecheck.TempAt(base.Pos, curfn, concretetyp)
	tmpok := typecheck.TempAt(base.Pos, curfn, types.Types[types.TBOOL])

	assert := ir.NewTypeAssertExpr(pos, recv, concretetyp)

	assertAsList := ir.NewAssignListStmt(pos, ir.OAS2, []ir.Node{tmpnode, tmpok}, []ir.Node{typecheck.Expr(assert)})
	init.Append(typecheck.Stmt(assertAsList))

	concreteCallee := typecheck.XDotMethod(pos, tmpnode, method, true)
	// Copy slice so edits in one location don't affect another.
	argvars = append([]ir.Node(nil), argvars...)
	concreteCall := typecheck.Call(pos, concreteCallee, argvars, call.IsDDD).(*ir.CallExpr)

	res := condCall(curfn, pos, tmpok, concreteCall, call, init)

	if base.Debug.PGODebug >= 3 {
		fmt.Printf("PGO devirtualizing interface call to %+v. After: %+v\n", concretetyp, res)
	}

	return res
}

// rewriteFunctionCall devirtualizes the given OCALLFUNC using a direct
// function call to callee.
func rewriteFunctionCall(call *ir.CallExpr, curfn, callee *ir.Func) ir.Node {
	if base.Flag.LowerM != 0 {
		fmt.Printf("%v: PGO devirtualizing function call %v to %v\n", ir.Line(call), call.Fun, callee)
	}

	// We generate an OINCALL of:
	//
	// var fn FuncType
	//
	// var arg1 A1
	// var argN AN
	//
	// var ret1 R1
	// var retN RN
	//
	// fn, arg1, argN = fn expr, arg1 expr, argN expr
	//
	// fnPC := internal/abi.FuncPCABIInternal(fn)
	// concretePC := internal/abi.FuncPCABIInternal(concrete)
	//
	// if fnPC == concretePC {
	//   ret1, retN = concrete(arg1, ... argN) // Same closure context passed (TODO)
	// } else {
	//   ret1, retN = fn(arg1, ... argN)
	// }
	//
	// OINCALL retvars: ret1, ... retN
	//
	// This isn't really an inlined call of course, but InlinedCallExpr
	// makes handling reassignment of return values easier.

	pos := call.Pos()
	init := ir.TakeInit(call)

	fn, args := copyInputs(curfn, pos, call.Fun, call.Args.Take(), &init)

	// Copy slice so edits in one location don't affect another.
	argvars := append([]ir.Node(nil), args...)
	call.Args = argvars

	// FuncPCABIInternal takes an interface{}, emulate that. This is needed
	// for to ensure we get the MAKEFACE we need for SSA.
	fnIface := typecheck.Expr(ir.NewConvExpr(pos, ir.OCONV, types.Types[types.TINTER], fn))
	calleeIface := typecheck.Expr(ir.NewConvExpr(pos, ir.OCONV, types.Types[types.TINTER], callee.Nname))

	fnPC := ir.FuncPC(pos, fnIface, obj.ABIInternal)
	concretePC := ir.FuncPC(pos, calleeIface, obj.ABIInternal)

	pcEq := typecheck.Expr(ir.NewBinaryExpr(base.Pos, ir.OEQ, fnPC, concretePC))

	// TODO(go.dev/issue/61577): Handle callees that a closures and need a
	// copy of the closure context from call. For now, we skip callees that
	// are closures in maybeDevirtualizeFunctionCall.
	if callee.OClosure != nil {
		base.Fatalf("Callee is a closure: %+v", callee)
	}

	// Copy slice so edits in one location don't affect another.
	argvars = append([]ir.Node(nil), argvars...)
	concreteCall := typecheck.Call(pos, callee.Nname, argvars, call.IsDDD).(*ir.CallExpr)

	res := condCall(curfn, pos, pcEq, concreteCall, call, init)

	if base.Debug.PGODebug >= 3 {
		fmt.Printf("PGO devirtualizing function call to %+v. After: %+v\n", ir.FuncName(callee), res)
	}

	return res
}

// methodRecvType returns the type containing method fn. Returns nil if fn
// is not a method.
func methodRecvType(fn *ir.Func) *types.Type {
	recv := fn.Nname.Type().Recv()
	if recv == nil {
		return nil
	}
	return recv.Type
}

// interfaceCallRecvTypeAndMethod returns the type and the method of the interface
// used in an interface call.
func interfaceCallRecvTypeAndMethod(call *ir.CallExpr) (*types.Type, *types.Sym) {
	if call.Op() != ir.OCALLINTER {
		base.Fatalf("Call isn't OCALLINTER: %+v", call)
	}

	sel, ok := call.Fun.(*ir.SelectorExpr)
	if !ok {
		base.Fatalf("OCALLINTER doesn't contain SelectorExpr: %+v", call)
	}

	return sel.X.Type(), sel.Sel
}

// findHotConcreteCallee returns the *ir.Func of the hottest callee of a call,
// if available, and its edge weight. extraFn can perform additional
// applicability checks on each candidate edge. If extraFn returns false,
// candidate will not be considered a valid callee candidate.
func findHotConcreteCallee(p *pgoir.Profile, caller *ir.Func, call *ir.CallExpr, extraFn func(callerName string, callOffset int, candidate *pgoir.IREdge) bool) (*ir.Func, int64) {
	callerName := ir.LinkFuncName(caller)
	callerNode := p.WeightedCG.IRNodes[callerName]
	callOffset := pgoir.NodeLineOffset(call, caller)

	if callerNode == nil {
		return nil, 0
	}

	var hottest *pgoir.IREdge

	// Returns true if e is hotter than hottest.
	//
	// Naively this is just e.Weight > hottest.Weight, but because OutEdges
	// has arbitrary iteration order, we need to apply additional sort
	// criteria when e.Weight == hottest.Weight to ensure we have stable
	// selection.
	hotter := func(e *pgoir.IREdge) bool {
		if hottest == nil {
			return true
		}
		if e.Weight != hottest.Weight {
			return e.Weight > hottest.Weight
		}

		// Now e.Weight == hottest.Weight, we must select on other
		// criteria.

		// If only one edge has IR, prefer that one.
		if (hottest.Dst.AST == nil) != (e.Dst.AST == nil) {
			if e.Dst.AST != nil {
				return true
			}
			return false
		}

		// Arbitrary, but the callee names will always differ. Select
		// the lexicographically first callee.
		return e.Dst.Name() < hottest.Dst.Name()
	}

	for _, e := range callerNode.OutEdges {
		if e.CallSiteOffset != callOffset {
			continue
		}

		if !hotter(e) {
			// TODO(prattmic): consider total caller weight? i.e.,
			// if the hottest callee is only 10% of the weight,
			// maybe don't devirtualize? Similarly, if this is call
			// is globally very cold, there is not much value in
			// devirtualizing.
			if base.Debug.PGODebug >= 2 {
				fmt.Printf("%v: edge %s:%d -> %s (weight %d): too cold (hottest %d)\n", ir.Line(call), callerName, callOffset, e.Dst.Name(), e.Weight, hottest.Weight)
			}
			continue
		}

		if e.Dst.AST == nil {
			// Destination isn't visible from this package
			// compilation.
			//
			// We must assume it implements the interface.
			//
			// We still record this as the hottest callee so far
			// because we only want to return the #1 hottest
			// callee. If we skip this then we'd return the #2
			// hottest callee.
			if base.Debug.PGODebug >= 2 {
				fmt.Printf("%v: edge %s:%d -> %s (weight %d) (missing IR): hottest so far\n", ir.Line(call), callerName, callOffset, e.Dst.Name(), e.Weight)
			}
			hottest = e
			continue
		}

		if extraFn != nil && !extraFn(callerName, callOffset, e) {
			continue
		}

		if base.Debug.PGODebug >= 2 {
			fmt.Printf("%v: edge %s:%d -> %s (weight %d): hottest so far\n", ir.Line(call), callerName, callOffset, e.Dst.Name(), e.Weight)
		}
		hottest = e
	}

	if hottest == nil {
		if base.Debug.PGODebug >= 2 {
			fmt.Printf("%v: call %s:%d: no hot callee\n", ir.Line(call), callerName, callOffset)
		}
		return nil, 0
	}

	if base.Debug.PGODebug >= 2 {
		fmt.Printf("%v: call %s:%d: hottest callee %s (weight %d)\n", ir.Line(call), callerName, callOffset, hottest.Dst.Name(), hottest.Weight)
	}
	return hottest.Dst.AST, hottest.Weight
}

// findHotConcreteInterfaceCallee returns the *ir.Func of the hottest callee of an
// interface call, if available, and its edge weight.
func findHotConcreteInterfaceCallee(p *pgoir.Profile, caller *ir.Func, call *ir.CallExpr) (*ir.Func, int64) {
	inter, method := interfaceCallRecvTypeAndMethod(call)

	return findHotConcreteCallee(p, caller, call, func(callerName string, callOffset int, e *pgoir.IREdge) bool {
		ctyp := methodRecvType(e.Dst.AST)
		if ctyp == nil {
			// Not a method.
			// TODO(prattmic): Support non-interface indirect calls.
			if base.Debug.PGODebug >= 2 {
				fmt.Printf("%v: edge %s:%d -> %s (weight %d): callee not a method\n", ir.Line(call), callerName, callOffset, e.Dst.Name(), e.Weight)
			}
			return false
		}

		// If ctyp doesn't implement inter it is most likely from a
		// different call on the same line
		if !typecheck.Implements(ctyp, inter) {
			// TODO(prattmic): this is overly strict. Consider if
			// ctyp is a partial implementation of an interface
			// that gets embedded in types that complete the
			// interface. It would still be OK to devirtualize a
			// call to this method.
			//
			// What we'd need to do is check that the function
			// pointer in the itab matches the method we want,
			// rather than doing a full type assertion.
			if base.Debug.PGODebug >= 2 {
				why := typecheck.ImplementsExplain(ctyp, inter)
				fmt.Printf("%v: edge %s:%d -> %s (weight %d): %v doesn't implement %v (%s)\n", ir.Line(call), callerName, callOffset, e.Dst.Name(), e.Weight, ctyp, inter, why)
			}
			return false
		}

		// If the method name is different it is most likely from a
		// different call on the same line
		if !strings.HasSuffix(e.Dst.Name(), "."+method.Name) {
			if base.Debug.PGODebug >= 2 {
				fmt.Printf("%v: edge %s:%d -> %s (weight %d): callee is a different method\n", ir.Line(call), callerName, callOffset, e.Dst.Name(), e.Weight)
			}
			return false
		}

		return true
	})
}

// findHotConcreteFunctionCallee returns the *ir.Func of the hottest callee of an
// indirect function call, if available, and its edge weight.
func findHotConcreteFunctionCallee(p *pgoir.Profile, caller *ir.Func, call *ir.CallExpr) (*ir.Func, int64) {
	typ := call.Fun.Type().Underlying()

	return findHotConcreteCallee(p, caller, call, func(callerName string, callOffset int, e *pgoir.IREdge) bool {
		ctyp := e.Dst.AST.Type().Underlying()

		// If ctyp doesn't match typ it is most likely from a different
		// call on the same line.
		//
		// Note that we are comparing underlying types, as different
		// defined types are OK. e.g., a call to a value of type
		// net/http.HandlerFunc can be devirtualized to a function with
		// the same underlying type.
		if !types.Identical(typ, ctyp) {
			if base.Debug.PGODebug >= 2 {
				fmt.Printf("%v: edge %s:%d -> %s (weight %d): %v doesn't match %v\n", ir.Line(call), callerName, callOffset, e.Dst.Name(), e.Weight, ctyp, typ)
			}
			return false
		}

		return true
	})
}
```