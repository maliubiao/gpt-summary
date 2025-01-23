Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understanding the Goal:** The request asks for the functionality of the `graph.go` file within the `pprof` tool. Specifically, it wants a functional description, example usage (where applicable), command-line argument handling (if any), and common pitfalls.

2. **Initial Scan and Keywords:** I first skimmed the code, looking for keywords and structural elements:
    * `package graph`:  This immediately tells me the core purpose is graph representation and manipulation.
    * `Graph`, `Node`, `Edge`, `Tag`: These are the fundamental data structures.
    * `Options`: This suggests configurable behavior.
    * `New`, `newGraph`, `newTree`: These are constructor-like functions, hinting at different ways to create a graph.
    * Regular expressions (`javaRegExp`, `goRegExp`, etc.): These indicate string manipulation, likely for simplifying function names.
    * Methods like `AddToEdge`, `addSample`, `TrimTree`, `SortNodes`:  These reveal the operations the `Graph` can perform.

3. **Deconstructing the Core Data Structures:** I focused on understanding `Graph`, `Node`, `Edge`, and `Tag`:
    * `Graph`: Contains a list of `Nodes`.
    * `Node`: Represents a program location. It has information about the location (`NodeInfo`), its function, values (flat and cumulative), incoming and outgoing edges, and tags. The concept of `Function *Node` is interesting – it suggests a way to represent function hierarchy or grouping.
    * `Edge`: Represents a connection between two `Nodes`, with a weight and flags like `Residual` and `Inline`.
    * `Tag`:  Represents annotations associated with a node, like labels or numeric values.

4. **Analyzing Key Functions:** I then examined the most important functions:
    * `New()`:  Acts as a factory, deciding whether to build a regular graph or a tree based on `Options`.
    * `newGraph()`:  The core logic for building a graph from a `profile.Profile`. It uses `CreateNodes` and then iterates through samples to populate node and edge weights. The `locationMap` is a key part, connecting profile locations to graph nodes.
    * `newTree()`:  Builds a call tree instead of a general graph. The use of `parentNodeMap` suggests how it maintains the tree structure.
    * `CreateNodes()`:  Responsible for creating the initial set of `Node` objects from the profile data. It handles cases where location information is incomplete.
    * `AddToEdge()`/`AddToEdgeDiv()`:  Methods to add or update edges between nodes.
    * `addSample()`:  Updates the values (flat, cum) and tags of a node based on a profile sample.
    * `TrimTree()`:  Specifically designed for trimming tree-like graphs based on a set of kept nodes. This method is complex and requires careful understanding of its logic, especially around edge manipulation.
    * `TrimLowFrequencyNodes()`, `TrimLowFrequencyEdges()`, `TrimLowFrequencyTags()`: Methods for filtering the graph based on value thresholds.
    * `SortNodes()`:  Allows sorting the nodes based on different criteria.

5. **Inferring Functionality and Examples:** Based on the data structures and functions, I could infer the overall purpose: to represent performance profiling data as a graph. I then thought about how to illustrate this with examples. The `New()` function takes a `profile.Profile` as input, so a simple example would involve creating a dummy profile and then using `graph.New()`. The different `Options` provide opportunities for showcasing different graph generation behaviors.

6. **Identifying Potential Pitfalls:**  I considered common mistakes users might make:
    * Misunderstanding the difference between `newGraph` and `newTree`.
    * Incorrectly using `TrimTree` on graphs that aren't trees (multiple parents).
    * Not understanding the implications of different `Options`.

7. **Command-Line Argument Handling:**  I looked for direct command-line parsing within this file but didn't find any. Since the code is part of the `pprof` tool, the command-line arguments would be handled at a higher level (likely in the `cmd/pprof` directory). The `Options` struct, however, *encodes* how those command-line options affect the graph construction.

8. **Structuring the Answer:**  I organized the information logically:
    * Start with a high-level summary of the file's purpose.
    * List the key functionalities.
    * Provide code examples to illustrate core concepts like graph creation.
    * Explain the role of the `Options` struct and how it relates to command-line parameters (even if the file doesn't directly handle them).
    * Detail the `TrimTree` function due to its complexity.
    * Discuss potential user errors.

9. **Refining the Language:** I ensured the language was clear, concise, and used appropriate technical terms. I also paid attention to the specific constraints of the prompt (using Chinese).

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This just builds a simple graph."  **Correction:**  Realized the distinction between `newGraph` and `newTree` is important, indicating more nuanced functionality.
* **Initial thought:** "The options are just internal." **Correction:**  Recognized that `Options` likely map to command-line flags in the broader `pprof` tool.
* **Struggled with `TrimTree` initially:**  The logic is a bit involved with its edge manipulation. **Resolution:**  Focused on explaining its precondition (it must be a tree) and the core steps of its operation.
* **Considered providing very detailed code examples for every function:** **Correction:** Realized that focusing on the core graph creation and the `Options` would be more effective in illustrating the main functionality. Overly detailed examples could be overwhelming.

By following these steps, iteratively analyzing the code, and refining my understanding, I arrived at the comprehensive explanation provided in the initial good answer.
这段代码是 Go 语言 `pprof` 工具中用于构建性能剖析图的一部分，位于 `go/src/cmd/vendor/github.com/google/pprof/internal/graph/graph.go`。它的主要功能是将性能剖析数据（`profile.Profile`）转换成一个有向图（`Graph`），以便进行分析和可视化。

**核心功能列举：**

1. **创建图的表示:** 定义了 `Graph` 结构体，用于存储由 `Node` 组成的图。
2. **节点和边的表示:** 定义了 `Node` 结构体表示图中的节点（通常代表程序中的一个函数或代码位置），以及 `Edge` 结构体表示节点之间的连接关系（调用关系）。
3. **节点信息的表示:** 定义了 `NodeInfo` 结构体，包含节点的详细信息，如函数名、文件名、行号、地址等。
4. **处理性能剖析数据:** `New` 函数是入口，它接收一个 `profile.Profile` 对象和一个 `Options` 对象，根据选项决定创建普通的图还是调用树。
5. **构建图的逻辑 (`newGraph`):**  遍历 `profile.Profile` 中的样本数据，将调用栈中的每个位置映射到 `Node` 对象，并根据调用关系创建 `Edge` 连接这些节点。同时，会聚合相同位置的样本数据，计算节点的 `Flat`（独占耗时）和 `Cum`（累计耗时）。
6. **构建调用树的逻辑 (`newTree`):**  类似于 `newGraph`，但它会构建一个严格的调用树结构，其中每个节点只有一个父节点。
7. **处理标签 (Tags):**  支持将剖析数据中的标签信息关联到图中的节点和边，用于更细粒度的分析。包括字符串标签 (`LabelTags`) 和数值标签 (`NumericTags`).
8. **过滤节点:**  提供根据累计值 (`Cum`) 过滤低频节点的功能 (`DiscardLowFrequencyNodes`, `DiscardLowFrequencyNodePtrs`)。
9. **过滤标签:** 提供根据权重过滤低频标签的功能 (`TrimLowFrequencyTags`)。
10. **过滤边:** 提供根据权重过滤低频边的功能 (`TrimLowFrequencyEdges`)。
11. **节点排序:**  提供多种节点排序方式 (`SortNodes`)，例如按照独占耗时、累计耗时、名称等排序，以便更好地理解性能瓶颈。
12. **选择头部节点:** 提供选择累计耗时最高的若干个节点的功能 (`SelectTopNodes`, `SelectTopNodePtrs`)。
13. **移除冗余边:** 提供移除图中冗余边（可以通过其他路径到达的节点之间的边）的功能 (`RemoveRedundantEdges`)，简化图的结构。
14. **缩短函数名:** 提供缩短函数名的功能 (`ShortenFunctionName`)，例如去除包名和参数，使图更易读。
15. **修剪调用树 (`TrimTree`):**  允许根据保留的节点集合来修剪调用树，移除不在集合中的节点和相应的边。

**Go 语言功能实现示例：**

以下是一个简化的示例，展示了如何使用 `graph` 包创建和操作图：

```go
package main

import (
	"fmt"
	"github.com/google/pprof/internal/graph"
	"github.com/google/pprof/profile"
)

func main() {
	// 假设我们有一个简单的 profile.Profile 对象
	prof := &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}},
		Sample: []*profile.Sample{
			{
				Value:    []int64{100}, // CPU nanoseconds
				Location: []*profile.Location{
					{
						ID: 1,
						Line: []profile.Line{{Function: &profile.Function{Name: "main.foo"}}},
					},
					{
						ID: 2,
						Line: []profile.Line{{Function: &profile.Function{Name: "main.bar"}}},
					},
				},
			},
			{
				Value:    []int64{50},
				Location: []*profile.Location{
					{
						ID: 1,
						Line: []profile.Line{{Function: &profile.Function{Name: "main.foo"}}},
					},
				},
			},
		},
		Location: []*profile.Location{
			{ID: 1, Line: []profile.Line{{Function: &profile.Function{Name: "main.foo"}}}},
			{ID: 2, Line: []profile.Line{{Function: &profile.Function{Name: "main.bar"}}}},
		},
	}

	// 创建 Graph 的选项
	opts := &graph.Options{
		SampleValue: func(v []int64) int64 {
			return v[0]
		},
	}

	// 创建图
	g := graph.New(prof, opts)

	// 打印图中的节点
	fmt.Println("Nodes in the graph:")
	for _, node := range g.Nodes {
		fmt.Printf("  %s (Flat: %d, Cum: %d)\n", node.Info.PrintableName(), node.FlatValue(), node.CumValue())
	}

	// 打印图中的边（简化起见，只打印了部分信息）
	fmt.Println("\nEdges in the graph:")
	for _, node := range g.Nodes {
		for _, edge := range node.Out {
			fmt.Printf("  %s -> %s (Weight: %d)\n", edge.Src.Info.PrintableName(), edge.Dest.Info.PrintableName(), edge.WeightValue())
		}
	}
}
```

**假设的输入与输出：**

对于上面的代码示例，假设输入的 `prof` 对象描述了 `main.foo` 调用了 `main.bar` 的情况。

**输出可能如下：**

```
Nodes in the graph:
  main.bar (Flat: 100, Cum: 100)
  main.foo (Flat: 50, Cum: 150)

Edges in the graph:
  main.foo -> main.bar (Weight: 100)
```

**代码推理：**

* `prof.Sample` 中的每个元素代表一个性能采样点，`Value` 包含了采样值（这里是 CPU 耗时），`Location` 包含了调用栈信息。
* `opts.SampleValue` 函数定义了如何从 `Sample.Value` 中提取用于计算节点和边权重的数值。
* `graph.New` 函数会遍历 `prof.Sample`，根据 `Location` 信息创建 `Node` 对象，并根据调用栈关系创建 `Edge` 对象。
* `Node.FlatValue()` 返回节点的独占耗时，`Node.CumValue()` 返回节点的累计耗时。
* `Edge.WeightValue()` 返回边的权重。

**命令行参数的具体处理：**

这段代码本身并没有直接处理命令行参数。`pprof` 工具的命令行参数解析通常发生在 `cmd/pprof` 目录下的代码中。然而，`Options` 结构体可以看作是命令行参数的一种映射。例如，命令行参数可能包含是否构建调用树、是否丢弃负值节点等，这些都会影响 `Options` 结构体的字段值，进而影响 `graph.New` 的行为。

例如，如果 `pprof` 工具接收了 `--call_tree` 参数，那么在创建 `Options` 对象时，`CallTree` 字段会被设置为 `true`，`graph.New` 就会调用 `newTree` 来构建调用树。

**使用者易犯错的点：**

1. **误解 `Flat` 和 `Cum` 的含义：**  `Flat` 是节点自身的耗时，不包括其调用的其他函数的耗时；`Cum` 是节点自身以及其所有下级调用的总耗时。混淆这两个概念会导致对性能数据的错误分析。

2. **在非树形结构上使用 `TrimTree`：** `TrimTree` 函数假设输入的是一个调用树（每个节点只有一个父节点）。如果在普通的图结构上使用 `TrimTree`，可能会导致 `panic`，因为代码中会检查节点是否有多于一个父节点。

   ```go
   // 假设 g 是一个普通的图，不是严格的调用树
   keptNodes := make(graph.NodePtrSet)
   // ... 向 keptNodes 中添加要保留的节点 ...

   // 错误的使用方式，如果 g 中存在多父节点的节点，会 panic
   // g.TrimTree(keptNodes)
   ```

3. **不理解 `Options` 的作用：**  `Options` 控制着图的构建方式。例如，如果 `SampleValue` 函数设置不正确，会导致计算出的节点和边权重不准确。

4. **忽略 `DropNegative` 的影响：** 如果设置了 `DropNegative` 为 `true`，那么累计值或独占值为负数的节点将会被移除，这可能会隐藏一些有用的信息，特别是当分析差异性剖析数据时。

5. **对排序方式理解不足：** `SortNodes` 提供了多种排序方式，每种方式都有其适用场景。不理解不同排序方式的含义可能导致无法找到关注的性能瓶颈。

总而言之，`go/src/cmd/vendor/github.com/google/pprof/internal/graph/graph.go` 文件是 `pprof` 工具中至关重要的组成部分，它负责将原始的性能剖析数据转换为易于分析和理解的图结构，为性能分析提供了基础的数据表示。 理解其功能和使用方式对于有效地使用 `pprof` 工具至关重要。

### 提示词
```
这是路径为go/src/cmd/vendor/github.com/google/pprof/internal/graph/graph.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package graph collects a set of samples into a directed graph.
package graph

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/pprof/profile"
)

var (
	// Removes package name and method arguments for Java method names.
	// See tests for examples.
	javaRegExp = regexp.MustCompile(`^(?:[a-z]\w*\.)*([A-Z][\w\$]*\.(?:<init>|[a-z][\w\$]*(?:\$\d+)?))(?:(?:\()|$)`)
	// Removes package name and method arguments for Go function names.
	// See tests for examples.
	goRegExp = regexp.MustCompile(`^(?:[\w\-\.]+\/)+([^.]+\..+)`)
	// Removes potential module versions in a package path.
	goVerRegExp = regexp.MustCompile(`^(.*?)/v(?:[2-9]|[1-9][0-9]+)([./].*)$`)
	// Strips C++ namespace prefix from a C++ function / method name.
	// NOTE: Make sure to keep the template parameters in the name. Normally,
	// template parameters are stripped from the C++ names but when
	// -symbolize=demangle=templates flag is used, they will not be.
	// See tests for examples.
	cppRegExp                = regexp.MustCompile(`^(?:[_a-zA-Z]\w*::)+(_*[A-Z]\w*::~?[_a-zA-Z]\w*(?:<.*>)?)`)
	cppAnonymousPrefixRegExp = regexp.MustCompile(`^\(anonymous namespace\)::`)
)

// Graph summarizes a performance profile into a format that is
// suitable for visualization.
type Graph struct {
	Nodes Nodes
}

// Options encodes the options for constructing a graph
type Options struct {
	SampleValue       func(s []int64) int64      // Function to compute the value of a sample
	SampleMeanDivisor func(s []int64) int64      // Function to compute the divisor for mean graphs, or nil
	FormatTag         func(int64, string) string // Function to format a sample tag value into a string
	ObjNames          bool                       // Always preserve obj filename
	OrigFnNames       bool                       // Preserve original (eg mangled) function names

	CallTree     bool // Build a tree instead of a graph
	DropNegative bool // Drop nodes with overall negative values

	KeptNodes NodeSet // If non-nil, only use nodes in this set
}

// Nodes is an ordered collection of graph nodes.
type Nodes []*Node

// Node is an entry on a profiling report. It represents a unique
// program location.
type Node struct {
	// Info describes the source location associated to this node.
	Info NodeInfo

	// Function represents the function that this node belongs to. On
	// graphs with sub-function resolution (eg line number or
	// addresses), two nodes in a NodeMap that are part of the same
	// function have the same value of Node.Function. If the Node
	// represents the whole function, it points back to itself.
	Function *Node

	// Values associated to this node. Flat is exclusive to this node,
	// Cum includes all descendents.
	Flat, FlatDiv, Cum, CumDiv int64

	// In and out Contains the nodes immediately reaching or reached by
	// this node.
	In, Out EdgeMap

	// LabelTags provide additional information about subsets of a sample.
	LabelTags TagMap

	// NumericTags provide additional values for subsets of a sample.
	// Numeric tags are optionally associated to a label tag. The key
	// for NumericTags is the name of the LabelTag they are associated
	// to, or "" for numeric tags not associated to a label tag.
	NumericTags map[string]TagMap
}

// FlatValue returns the exclusive value for this node, computing the
// mean if a divisor is available.
func (n *Node) FlatValue() int64 {
	if n.FlatDiv == 0 {
		return n.Flat
	}
	return n.Flat / n.FlatDiv
}

// CumValue returns the inclusive value for this node, computing the
// mean if a divisor is available.
func (n *Node) CumValue() int64 {
	if n.CumDiv == 0 {
		return n.Cum
	}
	return n.Cum / n.CumDiv
}

// AddToEdge increases the weight of an edge between two nodes. If
// there isn't such an edge one is created.
func (n *Node) AddToEdge(to *Node, v int64, residual, inline bool) {
	n.AddToEdgeDiv(to, 0, v, residual, inline)
}

// AddToEdgeDiv increases the weight of an edge between two nodes. If
// there isn't such an edge one is created.
func (n *Node) AddToEdgeDiv(to *Node, dv, v int64, residual, inline bool) {
	if n.Out[to] != to.In[n] {
		panic(fmt.Errorf("asymmetric edges %v %v", *n, *to))
	}

	if e := n.Out[to]; e != nil {
		e.WeightDiv += dv
		e.Weight += v
		if residual {
			e.Residual = true
		}
		if !inline {
			e.Inline = false
		}
		return
	}

	info := &Edge{Src: n, Dest: to, WeightDiv: dv, Weight: v, Residual: residual, Inline: inline}
	n.Out[to] = info
	to.In[n] = info
}

// NodeInfo contains the attributes for a node.
type NodeInfo struct {
	Name              string
	OrigName          string
	Address           uint64
	File              string
	StartLine, Lineno int
	Columnno          int
	Objfile           string
}

// PrintableName calls the Node's Formatter function with a single space separator.
func (i *NodeInfo) PrintableName() string {
	return strings.Join(i.NameComponents(), " ")
}

// NameComponents returns the components of the printable name to be used for a node.
func (i *NodeInfo) NameComponents() []string {
	var name []string
	if i.Address != 0 {
		name = append(name, fmt.Sprintf("%016x", i.Address))
	}
	if fun := i.Name; fun != "" {
		name = append(name, fun)
	}

	switch {
	case i.Lineno != 0:
		s := fmt.Sprintf("%s:%d", i.File, i.Lineno)
		if i.Columnno != 0 {
			s += fmt.Sprintf(":%d", i.Columnno)
		}
		// User requested line numbers, provide what we have.
		name = append(name, s)
	case i.File != "":
		// User requested file name, provide it.
		name = append(name, i.File)
	case i.Name != "":
		// User requested function name. It was already included.
	case i.Objfile != "":
		// Only binary name is available
		name = append(name, "["+filepath.Base(i.Objfile)+"]")
	default:
		// Do not leave it empty if there is no information at all.
		name = append(name, "<unknown>")
	}
	return name
}

// NodeMap maps from a node info struct to a node. It is used to merge
// report entries with the same info.
type NodeMap map[NodeInfo]*Node

// NodeSet is a collection of node info structs.
type NodeSet map[NodeInfo]bool

// NodePtrSet is a collection of nodes. Trimming a graph or tree requires a set
// of objects which uniquely identify the nodes to keep. In a graph, NodeInfo
// works as a unique identifier; however, in a tree multiple nodes may share
// identical NodeInfos. A *Node does uniquely identify a node so we can use that
// instead. Though a *Node also uniquely identifies a node in a graph,
// currently, during trimming, graphs are rebuilt from scratch using only the
// NodeSet, so there would not be the required context of the initial graph to
// allow for the use of *Node.
type NodePtrSet map[*Node]bool

// FindOrInsertNode takes the info for a node and either returns a matching node
// from the node map if one exists, or adds one to the map if one does not.
// If kept is non-nil, nodes are only added if they can be located on it.
func (nm NodeMap) FindOrInsertNode(info NodeInfo, kept NodeSet) *Node {
	if kept != nil {
		if _, ok := kept[info]; !ok {
			return nil
		}
	}

	if n, ok := nm[info]; ok {
		return n
	}

	n := &Node{
		Info:        info,
		In:          make(EdgeMap),
		Out:         make(EdgeMap),
		LabelTags:   make(TagMap),
		NumericTags: make(map[string]TagMap),
	}
	nm[info] = n
	if info.Address == 0 && info.Lineno == 0 {
		// This node represents the whole function, so point Function
		// back to itself.
		n.Function = n
		return n
	}
	// Find a node that represents the whole function.
	info.Address = 0
	info.Lineno = 0
	info.Columnno = 0
	n.Function = nm.FindOrInsertNode(info, nil)
	return n
}

// EdgeMap is used to represent the incoming/outgoing edges from a node.
type EdgeMap map[*Node]*Edge

// Edge contains any attributes to be represented about edges in a graph.
type Edge struct {
	Src, Dest *Node
	// The summary weight of the edge
	Weight, WeightDiv int64

	// residual edges connect nodes that were connected through a
	// separate node, which has been removed from the report.
	Residual bool
	// An inline edge represents a call that was inlined into the caller.
	Inline bool
}

// WeightValue returns the weight value for this edge, normalizing if a
// divisor is available.
func (e *Edge) WeightValue() int64 {
	if e.WeightDiv == 0 {
		return e.Weight
	}
	return e.Weight / e.WeightDiv
}

// Tag represent sample annotations
type Tag struct {
	Name          string
	Unit          string // Describe the value, "" for non-numeric tags
	Value         int64
	Flat, FlatDiv int64
	Cum, CumDiv   int64
}

// FlatValue returns the exclusive value for this tag, computing the
// mean if a divisor is available.
func (t *Tag) FlatValue() int64 {
	if t.FlatDiv == 0 {
		return t.Flat
	}
	return t.Flat / t.FlatDiv
}

// CumValue returns the inclusive value for this tag, computing the
// mean if a divisor is available.
func (t *Tag) CumValue() int64 {
	if t.CumDiv == 0 {
		return t.Cum
	}
	return t.Cum / t.CumDiv
}

// TagMap is a collection of tags, classified by their name.
type TagMap map[string]*Tag

// SortTags sorts a slice of tags based on their weight.
func SortTags(t []*Tag, flat bool) []*Tag {
	ts := tags{t, flat}
	sort.Sort(ts)
	return ts.t
}

// New summarizes performance data from a profile into a graph.
func New(prof *profile.Profile, o *Options) *Graph {
	if o.CallTree {
		return newTree(prof, o)
	}
	g, _ := newGraph(prof, o)
	return g
}

// newGraph computes a graph from a profile. It returns the graph, and
// a map from the profile location indices to the corresponding graph
// nodes.
func newGraph(prof *profile.Profile, o *Options) (*Graph, map[uint64]Nodes) {
	nodes, locationMap := CreateNodes(prof, o)
	seenNode := make(map[*Node]bool)
	seenEdge := make(map[nodePair]bool)
	for _, sample := range prof.Sample {
		var w, dw int64
		w = o.SampleValue(sample.Value)
		if o.SampleMeanDivisor != nil {
			dw = o.SampleMeanDivisor(sample.Value)
		}
		if dw == 0 && w == 0 {
			continue
		}
		for k := range seenNode {
			delete(seenNode, k)
		}
		for k := range seenEdge {
			delete(seenEdge, k)
		}
		var parent *Node
		// A residual edge goes over one or more nodes that were not kept.
		residual := false

		labels := joinLabels(sample)
		// Group the sample frames, based on a global map.
		for i := len(sample.Location) - 1; i >= 0; i-- {
			l := sample.Location[i]
			locNodes := locationMap[l.ID]
			for ni := len(locNodes) - 1; ni >= 0; ni-- {
				n := locNodes[ni]
				if n == nil {
					residual = true
					continue
				}
				// Add cum weight to all nodes in stack, avoiding double counting.
				if _, ok := seenNode[n]; !ok {
					seenNode[n] = true
					n.addSample(dw, w, labels, sample.NumLabel, sample.NumUnit, o.FormatTag, false)
				}
				// Update edge weights for all edges in stack, avoiding double counting.
				if _, ok := seenEdge[nodePair{n, parent}]; !ok && parent != nil && n != parent {
					seenEdge[nodePair{n, parent}] = true
					parent.AddToEdgeDiv(n, dw, w, residual, ni != len(locNodes)-1)
				}
				parent = n
				residual = false
			}
		}
		if parent != nil && !residual {
			// Add flat weight to leaf node.
			parent.addSample(dw, w, labels, sample.NumLabel, sample.NumUnit, o.FormatTag, true)
		}
	}

	return selectNodesForGraph(nodes, o.DropNegative), locationMap
}

func selectNodesForGraph(nodes Nodes, dropNegative bool) *Graph {
	// Collect nodes into a graph.
	gNodes := make(Nodes, 0, len(nodes))
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if n.Cum == 0 && n.Flat == 0 {
			continue
		}
		if dropNegative && isNegative(n) {
			continue
		}
		gNodes = append(gNodes, n)
	}
	return &Graph{gNodes}
}

type nodePair struct {
	src, dest *Node
}

func newTree(prof *profile.Profile, o *Options) (g *Graph) {
	parentNodeMap := make(map[*Node]NodeMap, len(prof.Sample))
	for _, sample := range prof.Sample {
		var w, dw int64
		w = o.SampleValue(sample.Value)
		if o.SampleMeanDivisor != nil {
			dw = o.SampleMeanDivisor(sample.Value)
		}
		if dw == 0 && w == 0 {
			continue
		}
		var parent *Node
		labels := joinLabels(sample)
		// Group the sample frames, based on a per-node map.
		for i := len(sample.Location) - 1; i >= 0; i-- {
			l := sample.Location[i]
			lines := l.Line
			if len(lines) == 0 {
				lines = []profile.Line{{}} // Create empty line to include location info.
			}
			for lidx := len(lines) - 1; lidx >= 0; lidx-- {
				nodeMap := parentNodeMap[parent]
				if nodeMap == nil {
					nodeMap = make(NodeMap)
					parentNodeMap[parent] = nodeMap
				}
				n := nodeMap.findOrInsertLine(l, lines[lidx], o)
				if n == nil {
					continue
				}
				n.addSample(dw, w, labels, sample.NumLabel, sample.NumUnit, o.FormatTag, false)
				if parent != nil {
					parent.AddToEdgeDiv(n, dw, w, false, lidx != len(lines)-1)
				}
				parent = n
			}
		}
		if parent != nil {
			parent.addSample(dw, w, labels, sample.NumLabel, sample.NumUnit, o.FormatTag, true)
		}
	}

	nodes := make(Nodes, 0, len(prof.Location))
	for _, nm := range parentNodeMap {
		nodes = append(nodes, nm.nodes()...)
	}
	return selectNodesForGraph(nodes, o.DropNegative)
}

// ShortenFunctionName returns a shortened version of a function's name.
func ShortenFunctionName(f string) string {
	f = cppAnonymousPrefixRegExp.ReplaceAllString(f, "")
	f = goVerRegExp.ReplaceAllString(f, `${1}${2}`)
	for _, re := range []*regexp.Regexp{goRegExp, javaRegExp, cppRegExp} {
		if matches := re.FindStringSubmatch(f); len(matches) >= 2 {
			return strings.Join(matches[1:], "")
		}
	}
	return f
}

// TrimTree trims a Graph in forest form, keeping only the nodes in kept. This
// will not work correctly if even a single node has multiple parents.
func (g *Graph) TrimTree(kept NodePtrSet) {
	// Creates a new list of nodes
	oldNodes := g.Nodes
	g.Nodes = make(Nodes, 0, len(kept))

	for _, cur := range oldNodes {
		// A node may not have multiple parents
		if len(cur.In) > 1 {
			panic("TrimTree only works on trees")
		}

		// If a node should be kept, add it to the new list of nodes
		if _, ok := kept[cur]; ok {
			g.Nodes = append(g.Nodes, cur)
			continue
		}

		// If a node has no parents, then delete all of the in edges of its
		// children to make them each roots of their own trees.
		if len(cur.In) == 0 {
			for _, outEdge := range cur.Out {
				delete(outEdge.Dest.In, cur)
			}
			continue
		}

		// Get the parent. This works since at this point cur.In must contain only
		// one element.
		if len(cur.In) != 1 {
			panic("Get parent assertion failed. cur.In expected to be of length 1.")
		}
		var parent *Node
		for _, edge := range cur.In {
			parent = edge.Src
		}

		parentEdgeInline := parent.Out[cur].Inline

		// Remove the edge from the parent to this node
		delete(parent.Out, cur)

		// Reconfigure every edge from the current node to now begin at the parent.
		for _, outEdge := range cur.Out {
			child := outEdge.Dest

			delete(child.In, cur)
			child.In[parent] = outEdge
			parent.Out[child] = outEdge

			outEdge.Src = parent
			outEdge.Residual = true
			// If the edge from the parent to the current node and the edge from the
			// current node to the child are both inline, then this resulting residual
			// edge should also be inline
			outEdge.Inline = parentEdgeInline && outEdge.Inline
		}
	}
	g.RemoveRedundantEdges()
}

func joinLabels(s *profile.Sample) string {
	if len(s.Label) == 0 {
		return ""
	}

	var labels []string
	for key, vals := range s.Label {
		for _, v := range vals {
			labels = append(labels, key+":"+v)
		}
	}
	sort.Strings(labels)
	return strings.Join(labels, `\n`)
}

// isNegative returns true if the node is considered as "negative" for the
// purposes of drop_negative.
func isNegative(n *Node) bool {
	switch {
	case n.Flat < 0:
		return true
	case n.Flat == 0 && n.Cum < 0:
		return true
	default:
		return false
	}
}

// CreateNodes creates graph nodes for all locations in a profile. It
// returns set of all nodes, plus a mapping of each location to the
// set of corresponding nodes (one per location.Line).
func CreateNodes(prof *profile.Profile, o *Options) (Nodes, map[uint64]Nodes) {
	locations := make(map[uint64]Nodes, len(prof.Location))
	nm := make(NodeMap, len(prof.Location))
	for _, l := range prof.Location {
		lines := l.Line
		if len(lines) == 0 {
			lines = []profile.Line{{}} // Create empty line to include location info.
		}
		nodes := make(Nodes, len(lines))
		for ln := range lines {
			nodes[ln] = nm.findOrInsertLine(l, lines[ln], o)
		}
		locations[l.ID] = nodes
	}
	return nm.nodes(), locations
}

func (nm NodeMap) nodes() Nodes {
	nodes := make(Nodes, 0, len(nm))
	for _, n := range nm {
		nodes = append(nodes, n)
	}
	return nodes
}

func (nm NodeMap) findOrInsertLine(l *profile.Location, li profile.Line, o *Options) *Node {
	var objfile string
	if m := l.Mapping; m != nil && m.File != "" {
		objfile = m.File
	}

	if ni := nodeInfo(l, li, objfile, o); ni != nil {
		return nm.FindOrInsertNode(*ni, o.KeptNodes)
	}
	return nil
}

func nodeInfo(l *profile.Location, line profile.Line, objfile string, o *Options) *NodeInfo {
	if line.Function == nil {
		return &NodeInfo{Address: l.Address, Objfile: objfile}
	}
	ni := &NodeInfo{
		Address:  l.Address,
		Lineno:   int(line.Line),
		Columnno: int(line.Column),
		Name:     line.Function.Name,
	}
	if fname := line.Function.Filename; fname != "" {
		ni.File = filepath.Clean(fname)
	}
	if o.OrigFnNames {
		ni.OrigName = line.Function.SystemName
	}
	if o.ObjNames || (ni.Name == "" && ni.OrigName == "") {
		ni.Objfile = objfile
		ni.StartLine = int(line.Function.StartLine)
	}
	return ni
}

type tags struct {
	t    []*Tag
	flat bool
}

func (t tags) Len() int      { return len(t.t) }
func (t tags) Swap(i, j int) { t.t[i], t.t[j] = t.t[j], t.t[i] }
func (t tags) Less(i, j int) bool {
	if !t.flat {
		if t.t[i].Cum != t.t[j].Cum {
			return abs64(t.t[i].Cum) > abs64(t.t[j].Cum)
		}
	}
	if t.t[i].Flat != t.t[j].Flat {
		return abs64(t.t[i].Flat) > abs64(t.t[j].Flat)
	}
	return t.t[i].Name < t.t[j].Name
}

// Sum adds the flat and cum values of a set of nodes.
func (ns Nodes) Sum() (flat int64, cum int64) {
	for _, n := range ns {
		flat += n.Flat
		cum += n.Cum
	}
	return
}

func (n *Node) addSample(dw, w int64, labels string, numLabel map[string][]int64, numUnit map[string][]string, format func(int64, string) string, flat bool) {
	// Update sample value
	if flat {
		n.FlatDiv += dw
		n.Flat += w
	} else {
		n.CumDiv += dw
		n.Cum += w
	}

	// Add string tags
	if labels != "" {
		t := n.LabelTags.findOrAddTag(labels, "", 0)
		if flat {
			t.FlatDiv += dw
			t.Flat += w
		} else {
			t.CumDiv += dw
			t.Cum += w
		}
	}

	numericTags := n.NumericTags[labels]
	if numericTags == nil {
		numericTags = TagMap{}
		n.NumericTags[labels] = numericTags
	}
	// Add numeric tags
	if format == nil {
		format = defaultLabelFormat
	}
	for k, nvals := range numLabel {
		units := numUnit[k]
		for i, v := range nvals {
			var t *Tag
			if len(units) > 0 {
				t = numericTags.findOrAddTag(format(v, units[i]), units[i], v)
			} else {
				t = numericTags.findOrAddTag(format(v, k), k, v)
			}
			if flat {
				t.FlatDiv += dw
				t.Flat += w
			} else {
				t.CumDiv += dw
				t.Cum += w
			}
		}
	}
}

func defaultLabelFormat(v int64, key string) string {
	return strconv.FormatInt(v, 10)
}

func (m TagMap) findOrAddTag(label, unit string, value int64) *Tag {
	l := m[label]
	if l == nil {
		l = &Tag{
			Name:  label,
			Unit:  unit,
			Value: value,
		}
		m[label] = l
	}
	return l
}

// String returns a text representation of a graph, for debugging purposes.
func (g *Graph) String() string {
	var s []string

	nodeIndex := make(map[*Node]int, len(g.Nodes))

	for i, n := range g.Nodes {
		nodeIndex[n] = i + 1
	}

	for i, n := range g.Nodes {
		name := n.Info.PrintableName()
		var in, out []int

		for _, from := range n.In {
			in = append(in, nodeIndex[from.Src])
		}
		for _, to := range n.Out {
			out = append(out, nodeIndex[to.Dest])
		}
		s = append(s, fmt.Sprintf("%d: %s[flat=%d cum=%d] %x -> %v ", i+1, name, n.Flat, n.Cum, in, out))
	}
	return strings.Join(s, "\n")
}

// DiscardLowFrequencyNodes returns a set of the nodes at or over a
// specific cum value cutoff.
func (g *Graph) DiscardLowFrequencyNodes(nodeCutoff int64) NodeSet {
	return makeNodeSet(g.Nodes, nodeCutoff)
}

// DiscardLowFrequencyNodePtrs returns a NodePtrSet of nodes at or over a
// specific cum value cutoff.
func (g *Graph) DiscardLowFrequencyNodePtrs(nodeCutoff int64) NodePtrSet {
	cutNodes := getNodesAboveCumCutoff(g.Nodes, nodeCutoff)
	kept := make(NodePtrSet, len(cutNodes))
	for _, n := range cutNodes {
		kept[n] = true
	}
	return kept
}

func makeNodeSet(nodes Nodes, nodeCutoff int64) NodeSet {
	cutNodes := getNodesAboveCumCutoff(nodes, nodeCutoff)
	kept := make(NodeSet, len(cutNodes))
	for _, n := range cutNodes {
		kept[n.Info] = true
	}
	return kept
}

// getNodesAboveCumCutoff returns all the nodes which have a Cum value greater
// than or equal to cutoff.
func getNodesAboveCumCutoff(nodes Nodes, nodeCutoff int64) Nodes {
	cutoffNodes := make(Nodes, 0, len(nodes))
	for _, n := range nodes {
		if abs64(n.Cum) < nodeCutoff {
			continue
		}
		cutoffNodes = append(cutoffNodes, n)
	}
	return cutoffNodes
}

// TrimLowFrequencyTags removes tags that have less than
// the specified weight.
func (g *Graph) TrimLowFrequencyTags(tagCutoff int64) {
	// Remove nodes with value <= total*nodeFraction
	for _, n := range g.Nodes {
		n.LabelTags = trimLowFreqTags(n.LabelTags, tagCutoff)
		for s, nt := range n.NumericTags {
			n.NumericTags[s] = trimLowFreqTags(nt, tagCutoff)
		}
	}
}

func trimLowFreqTags(tags TagMap, minValue int64) TagMap {
	kept := TagMap{}
	for s, t := range tags {
		if abs64(t.Flat) >= minValue || abs64(t.Cum) >= minValue {
			kept[s] = t
		}
	}
	return kept
}

// TrimLowFrequencyEdges removes edges that have less than
// the specified weight. Returns the number of edges removed
func (g *Graph) TrimLowFrequencyEdges(edgeCutoff int64) int {
	var droppedEdges int
	for _, n := range g.Nodes {
		for src, e := range n.In {
			if abs64(e.Weight) < edgeCutoff {
				delete(n.In, src)
				delete(src.Out, n)
				droppedEdges++
			}
		}
	}
	return droppedEdges
}

// SortNodes sorts the nodes in a graph based on a specific heuristic.
func (g *Graph) SortNodes(cum bool, visualMode bool) {
	// Sort nodes based on requested mode
	switch {
	case visualMode:
		// Specialized sort to produce a more visually-interesting graph
		g.Nodes.Sort(EntropyOrder)
	case cum:
		g.Nodes.Sort(CumNameOrder)
	default:
		g.Nodes.Sort(FlatNameOrder)
	}
}

// SelectTopNodePtrs returns a set of the top maxNodes *Node in a graph.
func (g *Graph) SelectTopNodePtrs(maxNodes int, visualMode bool) NodePtrSet {
	set := make(NodePtrSet)
	for _, node := range g.selectTopNodes(maxNodes, visualMode) {
		set[node] = true
	}
	return set
}

// SelectTopNodes returns a set of the top maxNodes nodes in a graph.
func (g *Graph) SelectTopNodes(maxNodes int, visualMode bool) NodeSet {
	return makeNodeSet(g.selectTopNodes(maxNodes, visualMode), 0)
}

// selectTopNodes returns a slice of the top maxNodes nodes in a graph.
func (g *Graph) selectTopNodes(maxNodes int, visualMode bool) Nodes {
	if maxNodes > 0 {
		if visualMode {
			var count int
			// If generating a visual graph, count tags as nodes. Update
			// maxNodes to account for them.
			for i, n := range g.Nodes {
				tags := countTags(n)
				if tags > maxNodelets {
					tags = maxNodelets
				}
				if count += tags + 1; count >= maxNodes {
					maxNodes = i + 1
					break
				}
			}
		}
	}
	if maxNodes > len(g.Nodes) {
		maxNodes = len(g.Nodes)
	}
	return g.Nodes[:maxNodes]
}

// countTags counts the tags with flat count. This underestimates the
// number of tags being displayed, but in practice is close enough.
func countTags(n *Node) int {
	count := 0
	for _, e := range n.LabelTags {
		if e.Flat != 0 {
			count++
		}
	}
	for _, t := range n.NumericTags {
		for _, e := range t {
			if e.Flat != 0 {
				count++
			}
		}
	}
	return count
}

// RemoveRedundantEdges removes residual edges if the destination can
// be reached through another path. This is done to simplify the graph
// while preserving connectivity.
func (g *Graph) RemoveRedundantEdges() {
	// Walk the nodes and outgoing edges in reverse order to prefer
	// removing edges with the lowest weight.
	for i := len(g.Nodes); i > 0; i-- {
		n := g.Nodes[i-1]
		in := n.In.Sort()
		for j := len(in); j > 0; j-- {
			e := in[j-1]
			if !e.Residual {
				// Do not remove edges heavier than a non-residual edge, to
				// avoid potential confusion.
				break
			}
			if isRedundantEdge(e) {
				delete(e.Src.Out, e.Dest)
				delete(e.Dest.In, e.Src)
			}
		}
	}
}

// isRedundantEdge determines if there is a path that allows e.Src
// to reach e.Dest after removing e.
func isRedundantEdge(e *Edge) bool {
	src, n := e.Src, e.Dest
	seen := map[*Node]bool{n: true}
	queue := Nodes{n}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, ie := range n.In {
			if e == ie || seen[ie.Src] {
				continue
			}
			if ie.Src == src {
				return true
			}
			seen[ie.Src] = true
			queue = append(queue, ie.Src)
		}
	}
	return false
}

// nodeSorter is a mechanism used to allow a report to be sorted
// in different ways.
type nodeSorter struct {
	rs   Nodes
	less func(l, r *Node) bool
}

func (s nodeSorter) Len() int           { return len(s.rs) }
func (s nodeSorter) Swap(i, j int)      { s.rs[i], s.rs[j] = s.rs[j], s.rs[i] }
func (s nodeSorter) Less(i, j int) bool { return s.less(s.rs[i], s.rs[j]) }

// Sort reorders a slice of nodes based on the specified ordering
// criteria. The result is sorted in decreasing order for (absolute)
// numeric quantities, alphabetically for text, and increasing for
// addresses.
func (ns Nodes) Sort(o NodeOrder) error {
	var s nodeSorter

	switch o {
	case FlatNameOrder:
		s = nodeSorter{ns,
			func(l, r *Node) bool {
				if iv, jv := abs64(l.Flat), abs64(r.Flat); iv != jv {
					return iv > jv
				}
				if iv, jv := l.Info.PrintableName(), r.Info.PrintableName(); iv != jv {
					return iv < jv
				}
				if iv, jv := abs64(l.Cum), abs64(r.Cum); iv != jv {
					return iv > jv
				}
				return compareNodes(l, r)
			},
		}
	case FlatCumNameOrder:
		s = nodeSorter{ns,
			func(l, r *Node) bool {
				if iv, jv := abs64(l.Flat), abs64(r.Flat); iv != jv {
					return iv > jv
				}
				if iv, jv := abs64(l.Cum), abs64(r.Cum); iv != jv {
					return iv > jv
				}
				if iv, jv := l.Info.PrintableName(), r.Info.PrintableName(); iv != jv {
					return iv < jv
				}
				return compareNodes(l, r)
			},
		}
	case NameOrder:
		s = nodeSorter{ns,
			func(l, r *Node) bool {
				if iv, jv := l.Info.Name, r.Info.Name; iv != jv {
					return iv < jv
				}
				return compareNodes(l, r)
			},
		}
	case FileOrder:
		s = nodeSorter{ns,
			func(l, r *Node) bool {
				if iv, jv := l.Info.File, r.Info.File; iv != jv {
					return iv < jv
				}
				if iv, jv := l.Info.StartLine, r.Info.StartLine; iv != jv {
					return iv < jv
				}
				return compareNodes(l, r)
			},
		}
	case AddressOrder:
		s = nodeSorter{ns,
			func(l, r *Node) bool {
				if iv, jv := l.Info.Address, r.Info.Address; iv != jv {
					return iv < jv
				}
				return compareNodes(l, r)
			},
		}
	case CumNameOrder, EntropyOrder:
		// Hold scoring for score-based ordering
		var score map[*Node]int64
		scoreOrder := func(l, r *Node) bool {
			if iv, jv := abs64(score[l]), abs64(score[r]); iv != jv {
				return iv > jv
			}
			if iv, jv := l.Info.PrintableName(), r.Info.PrintableName(); iv != jv {
				return iv < jv
			}
			if iv, jv := abs64(l.Flat), abs64(r.Flat); iv != jv {
				return iv > jv
			}
			return compareNodes(l, r)
		}

		switch o {
		case CumNameOrder:
			score = make(map[*Node]int64, len(ns))
			for _, n := range ns {
				score[n] = n.Cum
			}
			s = nodeSorter{ns, scoreOrder}
		case EntropyOrder:
			score = make(map[*Node]int64, len(ns))
			for _, n := range ns {
				score[n] = entropyScore(n)
			}
			s = nodeSorter{ns, scoreOrder}
		}
	default:
		return fmt.Errorf("report: unrecognized sort ordering: %d", o)
	}
	sort.Sort(s)
	return nil
}

// compareNodes compares two nodes to provide a deterministic ordering
// between them. Two nodes cannot have the same Node.Info value.
func compareNodes(l, r *Node) bool {
	return fmt.Sprint(l.Info) < fmt.Sprint(r.Info)
}

// entropyScore computes a score for a node representing how important
// it is to include this node on a graph visualization. It is used to
// sort the nodes and select which ones to display if we have more
// nodes than desired in the graph. This number is computed by looking
// at the flat and cum weights of the node and the incoming/outgoing
// edges. The fundamental idea is to penalize nodes that have a simple
// fallthrough from their incoming to the outgoing edge.
func entropyScore(n *Node) int64 {
	score := float64(0)

	if len(n.In) == 0 {
		score++ // Favor entry nodes
	} else {
		score += edgeEntropyScore(n, n.In, 0)
	}

	if len(n.Out) == 0 {
		score++ // Favor leaf nodes
	} else {
		score += edgeEntropyScore(n, n.Out, n.Flat)
	}

	return int64(score*float64(n.Cum)) + n.Flat
}

// edgeEntropyScore computes the entropy value for a set of edges
// coming in or out of a node. Entropy (as defined in information
// theory) refers to the amount of information encoded by the set of
// edges. A set of edges that have a more interesting distribution of
// samples gets a higher score.
func edgeEntropyScore(n *Node, edges EdgeMap, self int64) float64 {
	score := float64(0)
	total := self
	for _, e := range edges {
		if e.Weight > 0 {
			total += abs64(e.Weight)
		}
	}
	if total != 0 {
		for _, e := range edges {
			frac := float64(abs64(e.Weight)) / float64(total)
			score += -frac * math.Log2(frac)
		}
		if self > 0 {
			frac := float64(abs64(self)) / float64(total)
			score += -frac * math.Log2(frac)
		}
	}
	return score
}

// NodeOrder sets the ordering for a Sort operation
type NodeOrder int

// Sorting options for node sort.
const (
	FlatNameOrder NodeOrder = iota
	FlatCumNameOrder
	CumNameOrder
	NameOrder
	FileOrder
	AddressOrder
	EntropyOrder
)

// Sort returns a slice of the edges in the map, in a consistent
// order. The sort order is first based on the edge weight
// (higher-to-lower) and then by the node names to avoid flakiness.
func (e EdgeMap) Sort() []*Edge {
	el := make(edgeList, 0, len(e))
	for _, w := range e {
		el = append(el, w)
	}

	sort.Sort(el)
	return el
}

// Sum returns the total weight for a set of nodes.
func (e EdgeMap) Sum() int64 {
	var ret int64
	for _, edge := range e {
		ret += edge.Weight
	}
	return ret
}

type edgeList []*Edge

func (el edgeList) Len() int {
	return len(el)
}

func (el edgeList) Less(i, j int) bool {
	if el[i].Weight != el[j].Weight {
		return abs64(el[i].Weight) > abs64(el[j].Weight)
	}

	from1 := el[i].Src.Info.PrintableName()
	from2 := el[j].Src.Info.PrintableName()
	if from1 != from2 {
		return from1 < from2
	}

	to1 := el[i].Dest.Info.PrintableName()
	to2 := el[j].Dest.Info.PrintableName()

	return to1 < to2
}

func (el edgeList) Swap(i, j int) {
	el[i], el[j] = el[j], el[i]
}

func abs64(i int64) int64 {
	if i < 0 {
		return -i
	}
	return i
}
```