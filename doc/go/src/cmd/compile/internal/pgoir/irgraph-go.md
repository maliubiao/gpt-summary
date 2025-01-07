Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Understand the Goal:** The request asks for the functionality of the code, potential Go feature it implements, code examples, command-line arguments, and common mistakes. The file path `go/src/cmd/compile/internal/pgoir/irgraph.go` immediately suggests it's part of the Go compiler and related to Profile Guided Optimization (PGO).

2. **Initial Skim and Identify Key Structures:**  Read through the code quickly to get a high-level understanding. Notice the core data structures: `IRGraph`, `IRNode`, `IREdge`, and `Profile`. These names are quite descriptive.

3. **Analyze Core Data Structures:**

   * **`IRGraph`:** The name suggests a graph representation of Intermediate Representation (IR) nodes. The `IRNodes` map, keyed by linker symbol name, confirms this. The comment mentioning merging with `Graph` further solidifies this.

   * **`IRNode`:** Represents a function. The `AST` field (likely an Abstract Syntax Tree node) points to the function's IR. `LinkerSymbolName` is used when the IR is missing (for external functions). `OutEdges` represents calls made from this function.

   * **`IREdge`:**  Represents a call between two functions. `Src`, `Dst`, `Weight`, and `CallSiteOffset` are the key attributes. The `CallSiteOffset` is particularly important, referring to the line offset within the caller function.

   * **`Profile`:**  Contains the raw PGO profile (`pgo.Profile`) and the `WeightedCG` (the `IRGraph` built from the profile). This confirms the connection to PGO.

4. **Analyze Key Functions:** Focus on the public or seemingly important functions:

   * **`New(profileFile string)`:**  This is the entry point for creating a `Profile`. It handles opening and parsing the profile file (both serialized and pprof formats). It also calls `createIRGraph`, a central function.

   * **`createIRGraph(namedEdgeMap pgo.NamedEdgeMap)`:** This function iterates through the functions in the current package and builds the `IRGraph` by calling `visitIR`. It also calls `addIndirectEdges`. The comments about the order of operations and the TODOs are important for understanding the nuances.

   * **`visitIR(fn *ir.Func, namedEdgeMap pgo.NamedEdgeMap, g *IRGraph)`:**  Adds a node to the graph for the given function and calls `createIRGraphEdge` to find its outgoing calls.

   * **`createIRGraphEdge(fn *ir.Func, callernode *IRNode, name string, namedEdgeMap pgo.NamedEdgeMap, g *IRGraph)`:**  Walks through the function's body to identify function calls (`OCALLFUNC`, `OCALLMETH`) and calls `addIREdge`.

   * **`addIREdge(...)`:** Adds an edge to the graph, retrieving the weight from the `namedEdgeMap`.

   * **`addIndirectEdges(...)`:** Handles edges derived directly from the profile, potentially for calls to functions outside the current compilation unit. The handling of missing IR and the `LookupFunc` mechanism are crucial here.

   * **`PrintWeightedCallGraphDOT(edgeThreshold float64)`:**  Generates a DOT representation of the call graph, useful for visualization. The `edgeThreshold` parameter is a key detail.

   * **`DirectCallee(fn ir.Node)`:** Determines the statically known target of a function call. This is important for direct call edges.

5. **Infer Functionality:** Based on the structures and functions, it's clear that this code builds a weighted call graph based on PGO profile data. The weights represent the frequency of calls. This graph is then used for optimizations like inlining and devirtualization. The comments about line numbers and `//line` directives also highlight a specific challenge in mapping profile data to source code.

6. **Connect to Go Features:** The most obvious Go feature is **Profile Guided Optimization (PGO)**. The package name, data structures, and function names all point to this.

7. **Construct Code Examples:**  Think about how PGO works. You need to compile with instrumentation, run the program to generate a profile, and then recompile using the profile. This naturally leads to the example commands. Highlighting the profile file argument (`-pgo=`) is crucial.

8. **Consider Command-Line Arguments:** The `-pgo` flag during compilation is the main command-line interaction point. Explain its purpose and how to provide the profile file.

9. **Identify Potential Mistakes:** Think about common issues when using PGO:
    * **Forgetting to generate the profile:**  No profile, no optimization.
    * **Using the wrong profile:**  Profile from a different execution scenario might be misleading.
    * **Profile path issues:**  Incorrect or inaccessible file path.

10. **Review and Refine:** Read through the analysis to ensure it's clear, concise, and accurate. Check for any missing pieces or areas that could be explained better. For instance, initially, I might just say "builds a call graph," but refining it to "weighted call graph based on PGO profile data" is more precise. Emphasizing the "IR" aspect is also important.

This iterative process of skimming, analyzing structures and functions, inferring functionality, and connecting to Go features, combined with practical considerations like command-line arguments and potential errors, leads to a comprehensive understanding of the code. The key is to move from the general to the specific, constantly referring back to the code for confirmation.
这段代码是 Go 编译器中用于处理 **Profile-Guided Optimization (PGO)** 的一部分，具体来说，它负责构建一个基于 PGO profile 数据的带权重的函数调用图（Weighted Call Graph），并将其与程序的中间表示 (IR) 相关联。

以下是它的主要功能：

1. **加载和解析 PGO Profile 数据:**
   - `New(profileFile string)` 函数负责打开指定的 PGO profile 文件，并根据文件格式（serialized 或 pprof）解析其中的数据。
   - 它使用了 `cmd/internal/pgo` 包来处理底层的 profile 数据解析。

2. **构建带权重的 IR 调用图 (`IRGraph`):**
   - `createIRGraph(namedEdgeMap pgo.NamedEdgeMap)` 函数是构建调用图的核心。
   - 它遍历当前编译包中的所有函数 (`ir.VisitFuncsBottomUp`)。
   - 对于每个函数，调用 `visitIR` 来处理函数体内的调用。
   - `visitIR` 会创建一个 `IRNode` 来表示该函数，并调用 `createIRGraphEdge` 来查找该函数体内的直接调用。
   - `createIRGraphEdge` 遍历函数体内的节点，识别函数调用 (`ir.OCALLFUNC`, `ir.OCALLMETH`)。
   - 对于每个直接调用，`addIREdge` 会在调用图上添加一条边 (`IREdge`)，连接调用者和被调用者，并从 `namedEdgeMap` 中获取该调用的权重。
   - `addIndirectEdges` 函数处理 profile 中记录的间接调用边。这些边可能指向当前包中不可见的函数，例如接口调用或通过函数变量的调用。它会尝试从 export data 中查找这些函数的信息。

3. **关联 IR 和 Profile 数据:**
   - `IRNode` 结构体包含指向 `ir.Func` 的指针 (`AST`)，可以将调用图的节点与实际的 Go 函数的 IR 结构关联起来。
   - `IREdge` 结构体包含 `CallSiteOffset`，表示调用发生的代码行相对于函数起始行的偏移量。这个偏移量的计算考虑了 `//line` 指令的影响，以匹配 pprof profile 中报告的行号。

4. **表示调用关系和权重:**
   - `IRGraph` 使用 `map[string]*IRNode` 来存储图的节点，键是函数的链接器符号名称。
   - `IRNode` 使用 `map[pgo.NamedCallEdge]*IREdge` 来存储该节点的所有出边，每条边都包含了调用目标、权重和调用点信息。
   - `IREdge` 的 `Weight` 字段存储了从 PGO profile 中获取的该调用发生的次数。

5. **辅助功能:**
   - `NodeLineOffset(n ir.Node, fn *ir.Func)` 函数计算 IR 节点相对于其所在函数的起始行的偏移量，考虑了 `//line` 指令的影响。
   - `DirectCallee(fn ir.Node)` 函数尝试静态地解析函数调用表达式，返回被调用的 `ir.Func`。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言编译器中 **Profile-Guided Optimization (PGO)** 功能的核心组成部分。PGO 是一种编译器优化技术，它利用程序运行时的性能数据（profile）来指导编译器的优化决策，例如函数内联、虚函数调用优化等。

**Go 代码举例说明:**

假设我们有以下 Go 代码：

```go
package main

import "fmt"

func add(a, b int) int {
	return a + b
}

func multiply(a, b int) int {
	return a * b
}

func calculate(op string, x, y int) int {
	if op == "add" {
		return add(x, y)
	} else if op == "mul" {
		return multiply(x, y)
	}
	return 0
}

func main() {
	fmt.Println(calculate("add", 5, 3))
	fmt.Println(calculate("mul", 2, 4))
	fmt.Println(calculate("add", 1, 2))
}
```

1. **生成 Profile 数据:**

   首先，我们需要使用 `-pgo=auto` 标志编译并运行程序，以生成 profile 数据：

   ```bash
   go build -pgo=auto main.go
   ./main
   ```

   这会在当前目录下生成一个名为 `default.pgo` 的 profile 文件。

2. **使用 Profile 数据重新编译:**

   然后，我们使用生成的 profile 文件重新编译程序：

   ```bash
   go build -pgo=default.pgo main.go
   ```

   在重新编译的过程中，`go/src/cmd/compile/internal/pgoir/irgraph.go` 中的代码会被用来加载 `default.pgo` 文件，构建调用图，并将其与程序的 IR 关联起来。

   **推理与假设的输入输出:**

   **假设输入 (`default.pgo` 内容，简化示例):**

   ```
   main.calculate:10 2
   main.add:3 2
   main.calculate:12 1
   main.multiply:7 1
   ```

   这表示 `main.calculate` 在第 10 行被调用了 2 次，调用了 `main.add`；`main.calculate` 在第 12 行被调用了 1 次，调用了 `main.multiply`。

   **`createIRGraph` 函数的假设输出 (简化表示):**

   `IRGraph` 将包含以下节点和边 (省略部分细节):

   ```
   IRNodes:
     "main.main": &IRNode{AST: *ir.Func(main.main), OutEdges: ...}
     "main.calculate": &IRNode{AST: *ir.Func(main.calculate), OutEdges: ...}
     "main.add": &IRNode{AST: *ir.Func(main.add), OutEdges: nil}
     "main.multiply": &IRNode{AST: *ir.Func(main.multiply), OutEdges: nil}

   Edges (main.main -> main.calculate):
     IREdge{Src: main.main, Dst: main.calculate, Weight: 3, CallSiteOffset: ...} // 假设 main 函数调用 calculate 的行偏移量

   Edges (main.calculate -> main.add):
     IREdge{Src: main.calculate, Dst: main.add, Weight: 2, CallSiteOffset: ...} // 假设 calculate 函数调用 add 的行偏移量

   Edges (main.calculate -> main.multiply):
     IREdge{Src: main.calculate, Dst: main.multiply, Weight: 1, CallSiteOffset: ...} // 假设 calculate 函数调用 multiply 的行偏移量
   ```

**命令行参数的具体处理:**

这段代码本身并不直接处理命令行参数。命令行参数的处理发生在 `cmd/compile/internal/gc` 包中的主编译流程中。

当使用 `-pgo` 编译选项时，编译器会执行以下操作：

- **`-pgo=auto`:**  编译器会尝试在当前目录下查找名为 `default.pgo` 的 profile 文件。如果找到，则使用该文件进行 PGO。编译后会生成一个新的 `default.pgo` 文件，用于后续的编译。
- **`-pgo=<profile_file>`:** 编译器会使用指定的 profile 文件进行 PGO。

`go/src/cmd/compile/internal/pgoir/irgraph.go` 中的 `New` 函数会被调用，并将 profile 文件的路径作为参数传入。该函数负责打开和解析指定的文件。

**使用者易犯错的点:**

1. **忘记生成 Profile 数据:** 在使用 PGO 之前，必须先运行一次程序以生成 profile 数据。如果直接使用 `-pgo=<profile_file>` 进行编译，但指定的 profile 文件不存在或为空，则 PGO 将不会生效或可能导致错误。

   **示例:**

   ```bash
   go build -pgo=myprofile.pgo main.go  # 如果 myprofile.pgo 不存在，编译可能出错或 PGO 不生效
   ```

2. **使用了错误的 Profile 数据:** 使用与当前代码不匹配的 profile 数据可能会导致次优的优化。例如，如果在修改代码后没有重新生成 profile 数据就进行编译，那么编译器可能会基于过时的 profile 信息进行优化，反而降低性能。

   **示例:**

   ```bash
   # 第一次编译运行生成 default.pgo
   go build -pgo=auto main.go
   ./main

   # 修改了 main.go 中的 calculate 函数，但没有重新生成 profile
   # ... 修改代码 ...

   go build -pgo=default.pgo main.go  # 使用了旧的 profile 数据
   ```

3. **Profile 文件路径错误:**  如果使用 `-pgo=<profile_file>` 指定了 profile 文件，但文件路径不正确，编译器将无法找到该文件，导致 PGO 失败。

   **示例:**

   ```bash
   go build -pgo=./profiles/myprofile.pgo main.go  # 如果 ./profiles/myprofile.pgo 不存在，编译可能出错
   ```

总而言之，`go/src/cmd/compile/internal/pgoir/irgraph.go` 是 Go 编译器中 PGO 功能的关键部分，它负责将程序的静态结构（IR）与动态运行时的性能数据（profile）联系起来，为后续的编译器优化提供指导。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/pgoir/irgraph.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// A note on line numbers: when working with line numbers, we always use the
// binary-visible relative line number. i.e., the line number as adjusted by
// //line directives (ctxt.InnermostPos(ir.Node.Pos()).RelLine()). Use
// NodeLineOffset to compute line offsets.
//
// If you are thinking, "wait, doesn't that just make things more complex than
// using the real line number?", then you are 100% correct. Unfortunately,
// pprof profiles generated by the runtime always contain line numbers as
// adjusted by //line directives (because that is what we put in pclntab). Thus
// for the best behavior when attempting to match the source with the profile
// it makes sense to use the same line number space.
//
// Some of the effects of this to keep in mind:
//
//  - For files without //line directives there is no impact, as RelLine() ==
//    Line().
//  - For functions entirely covered by the same //line directive (i.e., a
//    directive before the function definition and no directives within the
//    function), there should also be no impact, as line offsets within the
//    function should be the same as the real line offsets.
//  - Functions containing //line directives may be impacted. As fake line
//    numbers need not be monotonic, we may compute negative line offsets. We
//    should accept these and attempt to use them for best-effort matching, as
//    these offsets should still match if the source is unchanged, and may
//    continue to match with changed source depending on the impact of the
//    changes on fake line numbers.
//  - Functions containing //line directives may also contain duplicate lines,
//    making it ambiguous which call the profile is referencing. This is a
//    similar problem to multiple calls on a single real line, as we don't
//    currently track column numbers.
//
// Long term it would be best to extend pprof profiles to include real line
// numbers. Until then, we have to live with these complexities. Luckily,
// //line directives that change line numbers in strange ways should be rare,
// and failing PGO matching on these files is not too big of a loss.

// Package pgoir associates a PGO profile with the IR of the current package
// compilation.
package pgoir

import (
	"bufio"
	"cmd/compile/internal/base"
	"cmd/compile/internal/ir"
	"cmd/compile/internal/typecheck"
	"cmd/compile/internal/types"
	"cmd/internal/pgo"
	"fmt"
	"maps"
	"os"
)

// IRGraph is a call graph with nodes pointing to IRs of functions and edges
// carrying weights and callsite information.
//
// Nodes for indirect calls may have missing IR (IRNode.AST == nil) if the node
// is not visible from this package (e.g., not in the transitive deps). Keeping
// these nodes allows determining the hottest edge from a call even if that
// callee is not available.
//
// TODO(prattmic): Consider merging this data structure with Graph. This is
// effectively a copy of Graph aggregated to line number and pointing to IR.
type IRGraph struct {
	// Nodes of the graph. Each node represents a function, keyed by linker
	// symbol name.
	IRNodes map[string]*IRNode
}

// IRNode represents a node (function) in the IRGraph.
type IRNode struct {
	// Pointer to the IR of the Function represented by this node.
	AST *ir.Func
	// Linker symbol name of the Function represented by this node.
	// Populated only if AST == nil.
	LinkerSymbolName string

	// Set of out-edges in the callgraph. The map uniquely identifies each
	// edge based on the callsite and callee, for fast lookup.
	OutEdges map[pgo.NamedCallEdge]*IREdge
}

// Name returns the symbol name of this function.
func (i *IRNode) Name() string {
	if i.AST != nil {
		return ir.LinkFuncName(i.AST)
	}
	return i.LinkerSymbolName
}

// IREdge represents a call edge in the IRGraph with source, destination,
// weight, callsite, and line number information.
type IREdge struct {
	// Source and destination of the edge in IRNode.
	Src, Dst       *IRNode
	Weight         int64
	CallSiteOffset int // Line offset from function start line.
}

// CallSiteInfo captures call-site information and its caller/callee.
type CallSiteInfo struct {
	LineOffset int // Line offset from function start line.
	Caller     *ir.Func
	Callee     *ir.Func
}

// Profile contains the processed PGO profile and weighted call graph used for
// PGO optimizations.
type Profile struct {
	// Profile is the base data from the raw profile, without IR attribution.
	*pgo.Profile

	// WeightedCG represents the IRGraph built from profile, which we will
	// update as part of inlining.
	WeightedCG *IRGraph
}

// New generates a profile-graph from the profile or pre-processed profile.
func New(profileFile string) (*Profile, error) {
	f, err := os.Open(profileFile)
	if err != nil {
		return nil, fmt.Errorf("error opening profile: %w", err)
	}
	defer f.Close()
	r := bufio.NewReader(f)

	isSerialized, err := pgo.IsSerialized(r)
	if err != nil {
		return nil, fmt.Errorf("error processing profile header: %w", err)
	}

	var base *pgo.Profile
	if isSerialized {
		base, err = pgo.FromSerialized(r)
		if err != nil {
			return nil, fmt.Errorf("error processing serialized PGO profile: %w", err)
		}
	} else {
		base, err = pgo.FromPProf(r)
		if err != nil {
			return nil, fmt.Errorf("error processing pprof PGO profile: %w", err)
		}
	}

	if base.TotalWeight == 0 {
		return nil, nil // accept but ignore profile with no samples.
	}

	// Create package-level call graph with weights from profile and IR.
	wg := createIRGraph(base.NamedEdgeMap)

	return &Profile{
		Profile:    base,
		WeightedCG: wg,
	}, nil
}

// initializeIRGraph builds the IRGraph by visiting all the ir.Func in decl list
// of a package.
func createIRGraph(namedEdgeMap pgo.NamedEdgeMap) *IRGraph {
	g := &IRGraph{
		IRNodes: make(map[string]*IRNode),
	}

	// Bottomup walk over the function to create IRGraph.
	ir.VisitFuncsBottomUp(typecheck.Target.Funcs, func(list []*ir.Func, recursive bool) {
		for _, fn := range list {
			visitIR(fn, namedEdgeMap, g)
		}
	})

	// Add additional edges for indirect calls. This must be done second so
	// that IRNodes is fully populated (see the dummy node TODO in
	// addIndirectEdges).
	//
	// TODO(prattmic): visitIR above populates the graph via direct calls
	// discovered via the IR. addIndirectEdges populates the graph via
	// calls discovered via the profile. This combination of opposite
	// approaches is a bit awkward, particularly because direct calls are
	// discoverable via the profile as well. Unify these into a single
	// approach.
	addIndirectEdges(g, namedEdgeMap)

	return g
}

// visitIR traverses the body of each ir.Func adds edges to g from ir.Func to
// any called function in the body.
func visitIR(fn *ir.Func, namedEdgeMap pgo.NamedEdgeMap, g *IRGraph) {
	name := ir.LinkFuncName(fn)
	node, ok := g.IRNodes[name]
	if !ok {
		node = &IRNode{
			AST: fn,
		}
		g.IRNodes[name] = node
	}

	// Recursively walk over the body of the function to create IRGraph edges.
	createIRGraphEdge(fn, node, name, namedEdgeMap, g)
}

// createIRGraphEdge traverses the nodes in the body of ir.Func and adds edges
// between the callernode which points to the ir.Func and the nodes in the
// body.
func createIRGraphEdge(fn *ir.Func, callernode *IRNode, name string, namedEdgeMap pgo.NamedEdgeMap, g *IRGraph) {
	ir.VisitList(fn.Body, func(n ir.Node) {
		switch n.Op() {
		case ir.OCALLFUNC:
			call := n.(*ir.CallExpr)
			// Find the callee function from the call site and add the edge.
			callee := DirectCallee(call.Fun)
			if callee != nil {
				addIREdge(callernode, name, n, callee, namedEdgeMap, g)
			}
		case ir.OCALLMETH:
			call := n.(*ir.CallExpr)
			// Find the callee method from the call site and add the edge.
			callee := ir.MethodExprName(call.Fun).Func
			addIREdge(callernode, name, n, callee, namedEdgeMap, g)
		}
	})
}

// NodeLineOffset returns the line offset of n in fn.
func NodeLineOffset(n ir.Node, fn *ir.Func) int {
	// See "A note on line numbers" at the top of the file.
	line := int(base.Ctxt.InnermostPos(n.Pos()).RelLine())
	startLine := int(base.Ctxt.InnermostPos(fn.Pos()).RelLine())
	return line - startLine
}

// addIREdge adds an edge between caller and new node that points to `callee`
// based on the profile-graph and NodeMap.
func addIREdge(callerNode *IRNode, callerName string, call ir.Node, callee *ir.Func, namedEdgeMap pgo.NamedEdgeMap, g *IRGraph) {
	calleeName := ir.LinkFuncName(callee)
	calleeNode, ok := g.IRNodes[calleeName]
	if !ok {
		calleeNode = &IRNode{
			AST: callee,
		}
		g.IRNodes[calleeName] = calleeNode
	}

	namedEdge := pgo.NamedCallEdge{
		CallerName:     callerName,
		CalleeName:     calleeName,
		CallSiteOffset: NodeLineOffset(call, callerNode.AST),
	}

	// Add edge in the IRGraph from caller to callee.
	edge := &IREdge{
		Src:            callerNode,
		Dst:            calleeNode,
		Weight:         namedEdgeMap.Weight[namedEdge],
		CallSiteOffset: namedEdge.CallSiteOffset,
	}

	if callerNode.OutEdges == nil {
		callerNode.OutEdges = make(map[pgo.NamedCallEdge]*IREdge)
	}
	callerNode.OutEdges[namedEdge] = edge
}

// LookupFunc looks up a function or method in export data. It is expected to
// be overridden by package noder, to break a dependency cycle.
var LookupFunc = func(fullName string) (*ir.Func, error) {
	base.Fatalf("pgoir.LookupMethodFunc not overridden")
	panic("unreachable")
}

// PostLookupCleanup performs any remaining cleanup operations needed
// after a series of calls to LookupFunc, specifically reading in the
// bodies of functions that may have been delayed due being encountered
// in a stage where the reader's curfn state was not set up.
var PostLookupCleanup = func() {
	base.Fatalf("pgoir.PostLookupCleanup not overridden")
	panic("unreachable")
}

// addIndirectEdges adds indirect call edges found in the profile to the graph,
// to be used for devirtualization.
//
// N.B. despite the name, addIndirectEdges will add any edges discovered via
// the profile. We don't know for sure that they are indirect, but assume they
// are since direct calls would already be added. (e.g., direct calls that have
// been deleted from source since the profile was taken would be added here).
//
// TODO(prattmic): Devirtualization runs before inlining, so we can't devirtualize
// calls inside inlined call bodies. If we did add that, we'd need edges from
// inlined bodies as well.
func addIndirectEdges(g *IRGraph, namedEdgeMap pgo.NamedEdgeMap) {
	// g.IRNodes is populated with the set of functions in the local
	// package build by VisitIR. We want to filter for local functions
	// below, but we also add unknown callees to IRNodes as we go. So make
	// an initial copy of IRNodes to recall just the local functions.
	localNodes := maps.Clone(g.IRNodes)

	// N.B. We must consider edges in a stable order because export data
	// lookup order (LookupMethodFunc, below) can impact the export data of
	// this package, which must be stable across different invocations for
	// reproducibility.
	//
	// The weight ordering of ByWeight is irrelevant, it just happens to be
	// an ordered list of edges that is already available.
	for _, key := range namedEdgeMap.ByWeight {
		weight := namedEdgeMap.Weight[key]
		// All callers in the local package build were added to IRNodes
		// in VisitIR. If a caller isn't in the local package build we
		// can skip adding edges, since we won't be devirtualizing in
		// them anyway. This keeps the graph smaller.
		callerNode, ok := localNodes[key.CallerName]
		if !ok {
			continue
		}

		// Already handled this edge?
		if _, ok := callerNode.OutEdges[key]; ok {
			continue
		}

		calleeNode, ok := g.IRNodes[key.CalleeName]
		if !ok {
			// IR is missing for this callee. VisitIR populates
			// IRNodes with all functions discovered via local
			// package function declarations and calls. This
			// function may still be available from export data of
			// a transitive dependency.
			//
			// TODO(prattmic): Parameterized types/functions are
			// not supported.
			//
			// TODO(prattmic): This eager lookup during graph load
			// is simple, but wasteful. We are likely to load many
			// functions that we never need. We could delay load
			// until we actually need the method in
			// devirtualization. Instantiation of generic functions
			// will likely need to be done at the devirtualization
			// site, if at all.
			if base.Debug.PGODebug >= 3 {
				fmt.Printf("addIndirectEdges: %s attempting export data lookup\n", key.CalleeName)
			}
			fn, err := LookupFunc(key.CalleeName)
			if err == nil {
				if base.Debug.PGODebug >= 3 {
					fmt.Printf("addIndirectEdges: %s found in export data\n", key.CalleeName)
				}
				calleeNode = &IRNode{AST: fn}

				// N.B. we could call createIRGraphEdge to add
				// direct calls in this newly-imported
				// function's body to the graph. Similarly, we
				// could add to this function's queue to add
				// indirect calls. However, those would be
				// useless given the visit order of inlining,
				// and the ordering of PGO devirtualization and
				// inlining. This function can only be used as
				// an inlined body. We will never do PGO
				// devirtualization inside an inlined call. Nor
				// will we perform inlining inside an inlined
				// call.
			} else {
				// Still not found. Most likely this is because
				// the callee isn't in the transitive deps of
				// this package.
				//
				// Record this call anyway. If this is the hottest,
				// then we want to skip devirtualization rather than
				// devirtualizing to the second most common callee.
				if base.Debug.PGODebug >= 3 {
					fmt.Printf("addIndirectEdges: %s not found in export data: %v\n", key.CalleeName, err)
				}
				calleeNode = &IRNode{LinkerSymbolName: key.CalleeName}
			}

			// Add dummy node back to IRNodes. We don't need this
			// directly, but PrintWeightedCallGraphDOT uses these
			// to print nodes.
			g.IRNodes[key.CalleeName] = calleeNode
		}
		edge := &IREdge{
			Src:            callerNode,
			Dst:            calleeNode,
			Weight:         weight,
			CallSiteOffset: key.CallSiteOffset,
		}

		if callerNode.OutEdges == nil {
			callerNode.OutEdges = make(map[pgo.NamedCallEdge]*IREdge)
		}
		callerNode.OutEdges[key] = edge
	}

	PostLookupCleanup()
}

// PrintWeightedCallGraphDOT prints IRGraph in DOT format.
func (p *Profile) PrintWeightedCallGraphDOT(edgeThreshold float64) {
	fmt.Printf("\ndigraph G {\n")
	fmt.Printf("forcelabels=true;\n")

	// List of functions in this package.
	funcs := make(map[string]struct{})
	ir.VisitFuncsBottomUp(typecheck.Target.Funcs, func(list []*ir.Func, recursive bool) {
		for _, f := range list {
			name := ir.LinkFuncName(f)
			funcs[name] = struct{}{}
		}
	})

	// Determine nodes of DOT.
	//
	// Note that ir.Func may be nil for functions not visible from this
	// package.
	nodes := make(map[string]*ir.Func)
	for name := range funcs {
		if n, ok := p.WeightedCG.IRNodes[name]; ok {
			for _, e := range n.OutEdges {
				if _, ok := nodes[e.Src.Name()]; !ok {
					nodes[e.Src.Name()] = e.Src.AST
				}
				if _, ok := nodes[e.Dst.Name()]; !ok {
					nodes[e.Dst.Name()] = e.Dst.AST
				}
			}
			if _, ok := nodes[n.Name()]; !ok {
				nodes[n.Name()] = n.AST
			}
		}
	}

	// Print nodes.
	for name, ast := range nodes {
		if _, ok := p.WeightedCG.IRNodes[name]; ok {
			style := "solid"
			if ast == nil {
				style = "dashed"
			}

			if ast != nil && ast.Inl != nil {
				fmt.Printf("\"%v\" [color=black, style=%s, label=\"%v,inl_cost=%d\"];\n", name, style, name, ast.Inl.Cost)
			} else {
				fmt.Printf("\"%v\" [color=black, style=%s, label=\"%v\"];\n", name, style, name)
			}
		}
	}
	// Print edges.
	ir.VisitFuncsBottomUp(typecheck.Target.Funcs, func(list []*ir.Func, recursive bool) {
		for _, f := range list {
			name := ir.LinkFuncName(f)
			if n, ok := p.WeightedCG.IRNodes[name]; ok {
				for _, e := range n.OutEdges {
					style := "solid"
					if e.Dst.AST == nil {
						style = "dashed"
					}
					color := "black"
					edgepercent := pgo.WeightInPercentage(e.Weight, p.TotalWeight)
					if edgepercent > edgeThreshold {
						color = "red"
					}

					fmt.Printf("edge [color=%s, style=%s];\n", color, style)
					fmt.Printf("\"%v\" -> \"%v\" [label=\"%.2f\"];\n", n.Name(), e.Dst.Name(), edgepercent)
				}
			}
		}
	})
	fmt.Printf("}\n")
}

// DirectCallee takes a function-typed expression and returns the underlying
// function that it refers to if statically known. Otherwise, it returns nil.
//
// Equivalent to inline.inlCallee without calling CanInline on closures.
func DirectCallee(fn ir.Node) *ir.Func {
	fn = ir.StaticValue(fn)
	switch fn.Op() {
	case ir.OMETHEXPR:
		fn := fn.(*ir.SelectorExpr)
		n := ir.MethodExprName(fn)
		// Check that receiver type matches fn.X.
		// TODO(mdempsky): Handle implicit dereference
		// of pointer receiver argument?
		if n == nil || !types.Identical(n.Type().Recv().Type, fn.X.Type()) {
			return nil
		}
		return n.Func
	case ir.ONAME:
		fn := fn.(*ir.Name)
		if fn.Class == ir.PFUNC {
			return fn.Func
		}
	case ir.OCLOSURE:
		fn := fn.(*ir.ClosureExpr)
		c := fn.Func
		return c
	}
	return nil
}

"""



```