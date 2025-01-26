Response:
Let's break down the thought process for analyzing the provided Go code snippet and generating the detailed explanation.

1. **Understanding the Request:** The request asks for an explanation of the Go code's functionality, including its purpose, examples, handling of command-line arguments (if any), and common pitfalls for users. The specific file path (`go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/callgraph/rta/rta.go`) provides context – it's related to static analysis, specifically call graph construction using Rapid Type Analysis (RTA).

2. **Initial Scan and Key Concepts:**  I quickly scanned the code, looking for keywords and structure. The package comment immediately reveals the core purpose: "Rapid Type Analysis (RTA) for Go," call graph construction, reachable code discovery, dead code detection, and runtime type identification. The mention of Bacon and Sweeney's paper provides a theoretical foundation. Key data structures like `Result`, `rta`, `Reachable`, `RuntimeTypes`, and `CallGraph` stand out.

3. **Decomposition by Functionality:** I started breaking down the code based on the comments and function names. I noticed distinct sections dealing with:

    * **Reachable Functions:**  `addReachable`
    * **Call Graph Edges:** `addEdge`
    * **Address-Taken Functions and Dynamic Calls:** `visitAddrTakenFunc`, `visitDynCall`
    * **Interface-Based Calls (Invoke):** `visitInvoke`, `addInvokeEdge`, `interfaces`, `implementations`
    * **Main Algorithm:** `visitFunc`, `Analyze`
    * **Runtime Types:** `addRuntimeType`

4. **Tracing the Data Flow:** I then tried to trace how data flows through the algorithm. The `Analyze` function seems to be the entry point. It initializes the `rta` struct and a worklist of root functions. The core logic resides in the `visitFunc` function, which iterates through the instructions of a function. Inside `visitFunc`, different types of instructions trigger specific actions:

    * `ssa.CallInstruction`: Handled differently based on whether it's a direct call, an interface invocation (`IsInvoke`), or a dynamic call.
    * `ssa.MakeInterface`:  Triggers the addition of a runtime type.
    * Operands of instructions: Checked for address-taken functions.

5. **Understanding the Core Algorithm (RTA):** The comments explicitly mention the cross-product tabulation for both direct calls and interface calls. This became a central point in my understanding. The algorithm iteratively discovers reachable functions and runtime types, adding edges to the call graph as it goes. The worklist mechanism ensures that newly discovered reachable functions are also processed.

6. **Identifying Key Data Structures and Their Roles:**

    * `Result`: Holds the final output of the analysis.
    * `rta`:  Encapsulates the working state of the algorithm.
    * `Reachable`: Tracks which functions are reachable and whether they are address-taken.
    * `RuntimeTypes`: Stores the set of types needed at runtime for interfaces and reflection.
    * `CallGraph`: Represents the call relationships between functions.
    * `addrTakenFuncsBySig`, `dynCallSites`, `invokeSites`, `concreteTypes`, `interfaceTypes`: These internal maps are crucial for the cross-product tabulation aspect of RTA.

7. **Formulating the Explanation:**  Based on the above understanding, I started structuring the explanation:

    * **Core Functionality:**  Summarize the main purpose of the code.
    * **Detailed Explanation of Key Functions:** Describe the role of each important function (`Analyze`, `visitFunc`, `addReachable`, etc.).
    * **Go Language Features:** Identify the Go features implemented (call graph construction, reachable code analysis, runtime type discovery).
    * **Code Example:** Create a simple Go example demonstrating how RTA works, focusing on direct calls, interface calls, and address-taken functions. This required making assumptions about the input SSA representation.
    * **Command-Line Arguments:**  Since the provided code snippet doesn't directly handle command-line arguments, I correctly stated that it focuses on the *core algorithm* and that other tools likely handle the CLI interface.
    * **Common Mistakes:**  Think about potential errors users might make when *using* a tool built with this RTA implementation. Misinterpreting the precision of RTA compared to pointer analysis is a key point. Also, the incompleteness of the call graph regarding reflection is important.

8. **Refining and Organizing:** I reviewed the explanation for clarity, accuracy, and completeness, ensuring the language was accessible and well-organized. I used headings and bullet points to improve readability. I also paid attention to the specific requirements of the prompt, like using Chinese.

9. **Self-Correction/Refinement during the process:**

    * **Initial thought:** "This looks like a simple call graph builder."  **Correction:** The comments highlight the "Rapid Type Analysis" aspect, which is more sophisticated than a basic call graph.
    * **Confusion:** Understanding the interaction between `concreteTypes` and `interfaceTypes` took some time. The "implements" relation and how it's used in the algorithm became clearer upon closer inspection of `interfaces` and `implementations`.
    * **Example Construction:**  Creating a concise yet illustrative example required some trial and error to choose the right code snippet that demonstrates the core RTA principles without being overly complex. I realized the example needed to generate an SSA representation to be truly representative, even if I only provided a simplified conceptual version in the final output.
    * **Command-line arguments:** Initially, I considered if there were any implicit CLI arguments. However, rereading the code confirmed its focus on the algorithmic part, deferring CLI handling to higher-level tools.

By following this structured approach, combining code analysis, conceptual understanding of RTA, and careful attention to the prompt's requirements, I arrived at the detailed and comprehensive explanation.
这段代码是 Go 语言中实现**快速类型分析 (Rapid Type Analysis, RTA)** 算法的一部分。RTA 是一种用于构建调用图和发现可达代码（以及死代码）以及运行时类型的快速静态分析算法。

**它的主要功能包括：**

1. **构建调用图 (Call Graph Construction):**  RTA 能够识别程序中函数之间的调用关系，并将其表示为一个图。`Result.CallGraph` 字段存储了构建的调用图。

2. **发现可达函数 (Reachable Function Discovery):**  RTA 确定程序执行过程中可能被调用的函数。`Result.Reachable` 字段存储了可达函数的集合。

3. **识别运行时类型 (Runtime Type Discovery):** RTA 识别在运行时可能出现的类型，尤其是在接口和反射场景中。`Result.RuntimeTypes` 字段存储了运行时类型的集合。

4. **处理直接函数调用 (Direct Function Calls):** 当遇到直接的函数调用时，RTA 会在调用图中添加一条从调用者到被调用者的边。

5. **处理动态函数调用 (Dynamic Function Calls via Interfaces and Function Values):**
   - **接口调用 (Interface Calls):** RTA 跟踪接口类型和实现该接口的具体类型，从而确定通过接口调用的目标函数。
   - **函数值调用 (Function Value Calls):** RTA 跟踪被赋值给函数变量的函数，从而确定通过函数值调用的目标函数。

6. **处理地址被获取的函数 (Address-Taken Functions):** 当函数的地址被获取时（例如，赋值给一个变量），RTA 会认为该函数可能被调用。

7. **处理反射 (Reflection):** RTA 考虑了通过反射可能调用的方法，并将运行时类型的导出方法标记为可达。

8. **使用工作列表 (Worklist) 算法:** RTA 使用工作列表来迭代地分析函数。当发现新的可达函数时，它会被添加到工作列表中进行进一步分析，直到达到一个不动点。

**它实现的 Go 语言功能：**

RTA 主要关注以下 Go 语言功能的静态分析：

* **函数调用 (Function Calls):**  包括直接调用和间接调用（通过接口或函数值）。
* **接口 (Interfaces):**  确定哪些具体类型实现了哪些接口，并用于解析接口调用。
* **函数类型 (Function Types):**  用于跟踪函数值的赋值和调用。
* **指针 (Pointers):**  虽然 RTA 不是一个精确的指针分析算法，但它会处理函数指针（地址被获取的函数）。
* **反射 (Reflection):**  识别可能通过反射调用的方法。
* **类型 (Types):**  跟踪运行时可能出现的类型。

**Go 代码示例 (假设的输入与输出):**

假设我们有以下 Go 代码：

```go
package main

import "fmt"

type MyInterface interface {
	DoSomething()
}

type MyStruct struct{}

func (ms MyStruct) DoSomething() {
	fmt.Println("MyStruct doing something")
}

func concreteFunc() {
	fmt.Println("Concrete function called")
}

func callInterface(i MyInterface) {
	i.DoSomething()
}

func main() {
	s := MyStruct{}
	callInterface(s) // 接口调用
	concreteFunc()    // 直接调用

	var fn func() = concreteFunc // 函数值赋值
	fn()                       // 函数值调用
}
```

**假设的 SSA 输入 (Simplified):**

```
// ... (SSA representation of the above code) ...

func main.main():
  block0:
    t0 = new MyStruct
    store t0, &s
    t1 = load &s
    call main.callInterface(t1)
    call main.concreteFunc()
    t2 = &main.concreteFunc
    store t2, &fn
    t3 = load &fn
    call t3()
    return

func main.callInterface(i MyInterface):
  block0:
    call i.DoSomething()
    return

func main.concreteFunc():
  block0:
    call fmt.Println("Concrete function called")
    return

// ... (SSA representation of MyStruct.DoSomething) ...
```

**RTA 的推理和输出 (简化):**

**假设 `Analyze` 函数的 `roots` 参数包含了 `main.main` 函数。**

1. **初始状态:** 工作列表包含 `main.main`。
2. **分析 `main.main`:**
   - 发现 `main.callInterface(s)` 调用。由于 `s` 是 `MyStruct` 类型，RTA 会将 `main.MyStruct` 添加到运行时类型，并查找 `MyStruct` 实现的接口 (`MyInterface`)。然后，它会解析接口调用到 `MyStruct.DoSomething` 并添加到调用图，并将 `MyStruct.DoSomething` 添加到可达函数。
   - 发现 `main.concreteFunc()` 调用，添加到调用图，并将 `main.concreteFunc` 添加到可达函数。
   - 发现函数值赋值 `fn = concreteFunc`。RTA 会记录 `concreteFunc` 的地址被获取。
   - 发现函数值调用 `fn()`。由于 `fn` 可能指向 `concreteFunc`，RTA 会添加到调用图。
3. **分析 `main.callInterface`:**  发现对 `i.DoSomething()` 的接口调用。根据已知的运行时类型 `main.MyStruct` 实现了 `MyInterface`，RTA 会将调用解析到 `MyStruct.DoSomething` (如果尚未添加)。
4. **分析 `main.concreteFunc` 和 `MyStruct.DoSomething`:**  RTA 会继续分析这些可达函数，查找更多的调用、地址被获取的函数和运行时类型。

**假设的 `Result` 输出:**

```go
Result{
    CallGraph: &callgraph.Graph{
        Nodes: {
            "main.main": {
                Edges: {
                    {Callee: "main.callInterface"},
                    {Callee: "main.concreteFunc"},
                    {Callee: "main.concreteFunc"}, // 通过函数值调用
                },
            },
            "main.callInterface": {
                Edges: {
                    {Callee: "main.(*MyStruct).DoSomething"},
                },
            },
            "main.concreteFunc": {
                // ... (可能调用了 fmt.Println)
            },
            "main.(*MyStruct).DoSomething": {
                // ... (可能调用了 fmt.Println)
            },
        },
    },
    Reachable: map[*ssa.Function]struct{ AddrTaken bool }{
        "main.main":                  {AddrTaken: false},
        "main.callInterface":         {AddrTaken: false},
        "main.concreteFunc":            {AddrTaken: true}, // 因为它的地址被获取了
        "main.(*MyStruct).DoSomething": {AddrTaken: false},
        // ... (fmt.Println 等)
    },
    RuntimeTypes: typeutil.Map{
        "main.MyStruct": struct{}{},
        // ... (其他可能用到的类型)
    },
}
```

**命令行参数:**

这段代码本身是 RTA 算法的实现，**不直接处理命令行参数**。它是一个库，会被其他工具（例如 `cmd/callgraph`）调用。这些工具可能会有命令行参数来指定要分析的包、输出格式等。

**使用者易犯错的点:**

1. **误解 RTA 的精度:**  RTA 是一种相对快速但不完全精确的调用图构建算法。它可能会产生一些**虚假的调用边**，即实际上运行时不会发生的调用。例如，如果一个接口类型有多个实现，RTA 可能会认为所有实现都可能被调用，即使在特定上下文中只有一部分会被调用。

   **示例:**

   ```go
   package main

   import "fmt"

   type MyInterface interface {
       DoSomething()
   }

   type ImplA struct{}
   func (ImplA) DoSomething() { fmt.Println("ImplA") }

   type ImplB struct{}
   func (ImplB) DoSomething() { fmt.Println("ImplB") }

   func main() {
       var i MyInterface
       if someCondition() {
           i = ImplA{}
       } else {
           i = ImplB{}
       }
       i.DoSomething() // RTA 可能认为 ImplA 和 ImplB 的 DoSomething 都会被调用
   }

   func someCondition() bool {
       return false // 实际只会调用 ImplB 的 DoSomething
   }
   ```

   RTA 会将 `ImplA.DoSomething` 和 `ImplB.DoSomething` 都标记为可能被调用，并添加到调用图中，即使在给定的 `main` 函数的执行路径中，只有一个会被实际调用。

2. **忽略反射调用的不确定性:**  虽然 RTA 会考虑反射，但反射调用的目标可能很难静态确定。RTA 可能会将所有导出的方法都标记为可达，但这可能不是运行时实际发生的情况。

总而言之，这段代码实现了 Go 语言的快速类型分析算法，用于构建调用图、发现可达代码和运行时类型。它通过迭代分析函数调用、接口、函数值和反射等特性来实现这些功能。使用者需要理解 RTA 的精度限制，避免过度依赖其生成的调用图进行需要高精度的分析。

Prompt: 
```
这是路径为go/src/github.com/alecthomas/gometalinter/_linters/src/honnef.co/go/tools/callgraph/rta/rta.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides Rapid Type Analysis (RTA) for Go, a fast
// algorithm for call graph construction and discovery of reachable code
// (and hence dead code) and runtime types.  The algorithm was first
// described in:
//
// David F. Bacon and Peter F. Sweeney. 1996.
// Fast static analysis of C++ virtual function calls. (OOPSLA '96)
// http://doi.acm.org/10.1145/236337.236371
//
// The algorithm uses dynamic programming to tabulate the cross-product
// of the set of known "address taken" functions with the set of known
// dynamic calls of the same type.  As each new address-taken function
// is discovered, call graph edges are added from each known callsite,
// and as each new call site is discovered, call graph edges are added
// from it to each known address-taken function.
//
// A similar approach is used for dynamic calls via interfaces: it
// tabulates the cross-product of the set of known "runtime types",
// i.e. types that may appear in an interface value, or be derived from
// one via reflection, with the set of known "invoke"-mode dynamic
// calls.  As each new "runtime type" is discovered, call edges are
// added from the known call sites, and as each new call site is
// discovered, call graph edges are added to each compatible
// method.
//
// In addition, we must consider all exported methods of any runtime type
// as reachable, since they may be called via reflection.
//
// Each time a newly added call edge causes a new function to become
// reachable, the code of that function is analyzed for more call sites,
// address-taken functions, and runtime types.  The process continues
// until a fixed point is achieved.
//
// The resulting call graph is less precise than one produced by pointer
// analysis, but the algorithm is much faster.  For example, running the
// cmd/callgraph tool on its own source takes ~2.1s for RTA and ~5.4s
// for points-to analysis.
//
package rta // import "honnef.co/go/tools/callgraph/rta"

// TODO(adonovan): test it by connecting it to the interpreter and
// replacing all "unreachable" functions by a special intrinsic, and
// ensure that that intrinsic is never called.

import (
	"fmt"
	"go/types"

	"honnef.co/go/tools/callgraph"
	"honnef.co/go/tools/ssa"
	"golang.org/x/tools/go/types/typeutil"
)

// A Result holds the results of Rapid Type Analysis, which includes the
// set of reachable functions/methods, runtime types, and the call graph.
//
type Result struct {
	// CallGraph is the discovered callgraph.
	// It does not include edges for calls made via reflection.
	CallGraph *callgraph.Graph

	// Reachable contains the set of reachable functions and methods.
	// This includes exported methods of runtime types, since
	// they may be accessed via reflection.
	// The value indicates whether the function is address-taken.
	//
	// (We wrap the bool in a struct to avoid inadvertent use of
	// "if Reachable[f] {" to test for set membership.)
	Reachable map[*ssa.Function]struct{ AddrTaken bool }

	// RuntimeTypes contains the set of types that are needed at
	// runtime, for interfaces or reflection.
	//
	// The value indicates whether the type is inaccessible to reflection.
	// Consider:
	// 	type A struct{B}
	// 	fmt.Println(new(A))
	// Types *A, A and B are accessible to reflection, but the unnamed
	// type struct{B} is not.
	RuntimeTypes typeutil.Map
}

// Working state of the RTA algorithm.
type rta struct {
	result *Result

	prog *ssa.Program

	worklist []*ssa.Function // list of functions to visit

	// addrTakenFuncsBySig contains all address-taken *Functions, grouped by signature.
	// Keys are *types.Signature, values are map[*ssa.Function]bool sets.
	addrTakenFuncsBySig typeutil.Map

	// dynCallSites contains all dynamic "call"-mode call sites, grouped by signature.
	// Keys are *types.Signature, values are unordered []ssa.CallInstruction.
	dynCallSites typeutil.Map

	// invokeSites contains all "invoke"-mode call sites, grouped by interface.
	// Keys are *types.Interface (never *types.Named),
	// Values are unordered []ssa.CallInstruction sets.
	invokeSites typeutil.Map

	// The following two maps together define the subset of the
	// m:n "implements" relation needed by the algorithm.

	// concreteTypes maps each concrete type to the set of interfaces that it implements.
	// Keys are types.Type, values are unordered []*types.Interface.
	// Only concrete types used as MakeInterface operands are included.
	concreteTypes typeutil.Map

	// interfaceTypes maps each interface type to
	// the set of concrete types that implement it.
	// Keys are *types.Interface, values are unordered []types.Type.
	// Only interfaces used in "invoke"-mode CallInstructions are included.
	interfaceTypes typeutil.Map
}

// addReachable marks a function as potentially callable at run-time,
// and ensures that it gets processed.
func (r *rta) addReachable(f *ssa.Function, addrTaken bool) {
	reachable := r.result.Reachable
	n := len(reachable)
	v := reachable[f]
	if addrTaken {
		v.AddrTaken = true
	}
	reachable[f] = v
	if len(reachable) > n {
		// First time seeing f.  Add it to the worklist.
		r.worklist = append(r.worklist, f)
	}
}

// addEdge adds the specified call graph edge, and marks it reachable.
// addrTaken indicates whether to mark the callee as "address-taken".
func (r *rta) addEdge(site ssa.CallInstruction, callee *ssa.Function, addrTaken bool) {
	r.addReachable(callee, addrTaken)

	if g := r.result.CallGraph; g != nil {
		if site.Parent() == nil {
			panic(site)
		}
		from := g.CreateNode(site.Parent())
		to := g.CreateNode(callee)
		callgraph.AddEdge(from, site, to)
	}
}

// ---------- addrTakenFuncs × dynCallSites ----------

// visitAddrTakenFunc is called each time we encounter an address-taken function f.
func (r *rta) visitAddrTakenFunc(f *ssa.Function) {
	// Create two-level map (Signature -> Function -> bool).
	S := f.Signature
	funcs, _ := r.addrTakenFuncsBySig.At(S).(map[*ssa.Function]bool)
	if funcs == nil {
		funcs = make(map[*ssa.Function]bool)
		r.addrTakenFuncsBySig.Set(S, funcs)
	}
	if !funcs[f] {
		// First time seeing f.
		funcs[f] = true

		// If we've seen any dyncalls of this type, mark it reachable,
		// and add call graph edges.
		sites, _ := r.dynCallSites.At(S).([]ssa.CallInstruction)
		for _, site := range sites {
			r.addEdge(site, f, true)
		}
	}
}

// visitDynCall is called each time we encounter a dynamic "call"-mode call.
func (r *rta) visitDynCall(site ssa.CallInstruction) {
	S := site.Common().Signature()

	// Record the call site.
	sites, _ := r.dynCallSites.At(S).([]ssa.CallInstruction)
	r.dynCallSites.Set(S, append(sites, site))

	// For each function of signature S that we know is address-taken,
	// mark it reachable.  We'll add the callgraph edges later.
	funcs, _ := r.addrTakenFuncsBySig.At(S).(map[*ssa.Function]bool)
	for g := range funcs {
		r.addEdge(site, g, true)
	}
}

// ---------- concrete types × invoke sites ----------

// addInvokeEdge is called for each new pair (site, C) in the matrix.
func (r *rta) addInvokeEdge(site ssa.CallInstruction, C types.Type) {
	// Ascertain the concrete method of C to be called.
	imethod := site.Common().Method
	cmethod := r.prog.MethodValue(r.prog.MethodSets.MethodSet(C).Lookup(imethod.Pkg(), imethod.Name()))
	r.addEdge(site, cmethod, true)
}

// visitInvoke is called each time the algorithm encounters an "invoke"-mode call.
func (r *rta) visitInvoke(site ssa.CallInstruction) {
	I := site.Common().Value.Type().Underlying().(*types.Interface)

	// Record the invoke site.
	sites, _ := r.invokeSites.At(I).([]ssa.CallInstruction)
	r.invokeSites.Set(I, append(sites, site))

	// Add callgraph edge for each existing
	// address-taken concrete type implementing I.
	for _, C := range r.implementations(I) {
		r.addInvokeEdge(site, C)
	}
}

// ---------- main algorithm ----------

// visitFunc processes function f.
func (r *rta) visitFunc(f *ssa.Function) {
	var space [32]*ssa.Value // preallocate space for common case

	for _, b := range f.Blocks {
		for _, instr := range b.Instrs {
			rands := instr.Operands(space[:0])

			switch instr := instr.(type) {
			case ssa.CallInstruction:
				call := instr.Common()
				if call.IsInvoke() {
					r.visitInvoke(instr)
				} else if g := call.StaticCallee(); g != nil {
					r.addEdge(instr, g, false)
				} else if _, ok := call.Value.(*ssa.Builtin); !ok {
					r.visitDynCall(instr)
				}

				// Ignore the call-position operand when
				// looking for address-taken Functions.
				// Hack: assume this is rands[0].
				rands = rands[1:]

			case *ssa.MakeInterface:
				r.addRuntimeType(instr.X.Type(), false)
			}

			// Process all address-taken functions.
			for _, op := range rands {
				if g, ok := (*op).(*ssa.Function); ok {
					r.visitAddrTakenFunc(g)
				}
			}
		}
	}
}

// Analyze performs Rapid Type Analysis, starting at the specified root
// functions.  It returns nil if no roots were specified.
//
// If buildCallGraph is true, Result.CallGraph will contain a call
// graph; otherwise, only the other fields (reachable functions) are
// populated.
//
func Analyze(roots []*ssa.Function, buildCallGraph bool) *Result {
	if len(roots) == 0 {
		return nil
	}

	r := &rta{
		result: &Result{Reachable: make(map[*ssa.Function]struct{ AddrTaken bool })},
		prog:   roots[0].Prog,
	}

	if buildCallGraph {
		// TODO(adonovan): change callgraph API to eliminate the
		// notion of a distinguished root node.  Some callgraphs
		// have many roots, or none.
		r.result.CallGraph = callgraph.New(roots[0])
	}

	hasher := typeutil.MakeHasher()
	r.result.RuntimeTypes.SetHasher(hasher)
	r.addrTakenFuncsBySig.SetHasher(hasher)
	r.dynCallSites.SetHasher(hasher)
	r.invokeSites.SetHasher(hasher)
	r.concreteTypes.SetHasher(hasher)
	r.interfaceTypes.SetHasher(hasher)

	// Visit functions, processing their instructions, and adding
	// new functions to the worklist, until a fixed point is
	// reached.
	var shadow []*ssa.Function // for efficiency, we double-buffer the worklist
	r.worklist = append(r.worklist, roots...)
	for len(r.worklist) > 0 {
		shadow, r.worklist = r.worklist, shadow[:0]
		for _, f := range shadow {
			r.visitFunc(f)
		}
	}
	return r.result
}

// interfaces(C) returns all currently known interfaces implemented by C.
func (r *rta) interfaces(C types.Type) []*types.Interface {
	// Ascertain set of interfaces C implements
	// and update 'implements' relation.
	var ifaces []*types.Interface
	r.interfaceTypes.Iterate(func(I types.Type, concs interface{}) {
		if I := I.(*types.Interface); types.Implements(C, I) {
			concs, _ := concs.([]types.Type)
			r.interfaceTypes.Set(I, append(concs, C))
			ifaces = append(ifaces, I)
		}
	})
	r.concreteTypes.Set(C, ifaces)
	return ifaces
}

// implementations(I) returns all currently known concrete types that implement I.
func (r *rta) implementations(I *types.Interface) []types.Type {
	var concs []types.Type
	if v := r.interfaceTypes.At(I); v != nil {
		concs = v.([]types.Type)
	} else {
		// First time seeing this interface.
		// Update the 'implements' relation.
		r.concreteTypes.Iterate(func(C types.Type, ifaces interface{}) {
			if types.Implements(C, I) {
				ifaces, _ := ifaces.([]*types.Interface)
				r.concreteTypes.Set(C, append(ifaces, I))
				concs = append(concs, C)
			}
		})
		r.interfaceTypes.Set(I, concs)
	}
	return concs
}

// addRuntimeType is called for each concrete type that can be the
// dynamic type of some interface or reflect.Value.
// Adapted from needMethods in go/ssa/builder.go
//
func (r *rta) addRuntimeType(T types.Type, skip bool) {
	if prev, ok := r.result.RuntimeTypes.At(T).(bool); ok {
		if skip && !prev {
			r.result.RuntimeTypes.Set(T, skip)
		}
		return
	}
	r.result.RuntimeTypes.Set(T, skip)

	mset := r.prog.MethodSets.MethodSet(T)

	if _, ok := T.Underlying().(*types.Interface); !ok {
		// T is a new concrete type.
		for i, n := 0, mset.Len(); i < n; i++ {
			sel := mset.At(i)
			m := sel.Obj()

			if m.Exported() {
				// Exported methods are always potentially callable via reflection.
				r.addReachable(r.prog.MethodValue(sel), true)
			}
		}

		// Add callgraph edge for each existing dynamic
		// "invoke"-mode call via that interface.
		for _, I := range r.interfaces(T) {
			sites, _ := r.invokeSites.At(I).([]ssa.CallInstruction)
			for _, site := range sites {
				r.addInvokeEdge(site, T)
			}
		}
	}

	// Precondition: T is not a method signature (*Signature with Recv()!=nil).
	// Recursive case: skip => don't call makeMethods(T).
	// Each package maintains its own set of types it has visited.

	var n *types.Named
	switch T := T.(type) {
	case *types.Named:
		n = T
	case *types.Pointer:
		n, _ = T.Elem().(*types.Named)
	}
	if n != nil {
		owner := n.Obj().Pkg()
		if owner == nil {
			return // built-in error type
		}
	}

	// Recursion over signatures of each exported method.
	for i := 0; i < mset.Len(); i++ {
		if mset.At(i).Obj().Exported() {
			sig := mset.At(i).Type().(*types.Signature)
			r.addRuntimeType(sig.Params(), true)  // skip the Tuple itself
			r.addRuntimeType(sig.Results(), true) // skip the Tuple itself
		}
	}

	switch t := T.(type) {
	case *types.Basic:
		// nop

	case *types.Interface:
		// nop---handled by recursion over method set.

	case *types.Pointer:
		r.addRuntimeType(t.Elem(), false)

	case *types.Slice:
		r.addRuntimeType(t.Elem(), false)

	case *types.Chan:
		r.addRuntimeType(t.Elem(), false)

	case *types.Map:
		r.addRuntimeType(t.Key(), false)
		r.addRuntimeType(t.Elem(), false)

	case *types.Signature:
		if t.Recv() != nil {
			panic(fmt.Sprintf("Signature %s has Recv %s", t, t.Recv()))
		}
		r.addRuntimeType(t.Params(), true)  // skip the Tuple itself
		r.addRuntimeType(t.Results(), true) // skip the Tuple itself

	case *types.Named:
		// A pointer-to-named type can be derived from a named
		// type via reflection.  It may have methods too.
		r.addRuntimeType(types.NewPointer(T), false)

		// Consider 'type T struct{S}' where S has methods.
		// Reflection provides no way to get from T to struct{S},
		// only to S, so the method set of struct{S} is unwanted,
		// so set 'skip' flag during recursion.
		r.addRuntimeType(t.Underlying(), true)

	case *types.Array:
		r.addRuntimeType(t.Elem(), false)

	case *types.Struct:
		for i, n := 0, t.NumFields(); i < n; i++ {
			r.addRuntimeType(t.Field(i).Type(), false)
		}

	case *types.Tuple:
		for i, n := 0, t.Len(); i < n; i++ {
			r.addRuntimeType(t.At(i).Type(), false)
		}

	default:
		panic(T)
	}
}

"""



```