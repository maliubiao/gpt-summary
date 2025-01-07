Response:
Let's break down the thought process for analyzing the `graph.go` file.

1. **Understand the Goal:** The initial prompt asks for the functionalities of the `graph.go` file, its potential use cases within Go profiling, and any common pitfalls. The key is to understand *what* this code does and *why* it exists.

2. **High-Level Overview:** Start by reading the package comment: `// Package profile represents a pprof profile as a directed graph.` This immediately tells us the core purpose: transforming profiling data into a graph structure. The "simplified fork" comment suggests it's based on a more comprehensive version, likely within the `pprof` tool itself.

3. **Identify Key Data Structures:** Scan the file for type definitions (`type`). The main ones that stand out are:
    * `Options`:  Configuration settings for graph construction. This is crucial as it controls how the graph is built.
    * `Node`: Represents a program location in the profile. It stores information like function name, line number, and performance metrics. The `In` and `Out` fields hint at graph edges.
    * `Nodes`: A slice of `Node` pointers.
    * `Graph`: The main graph structure containing a collection of `Nodes`.
    * `NodeInfo`: Details about a specific code location.
    * `NodeMap`: A map to efficiently find or create `Node`s based on `NodeInfo`. This is important for merging duplicate entries.
    * `NodeSet`, `NodePtrSet`: Sets for storing node information, used for filtering or identifying nodes.
    * `Edge`: Represents a relationship (e.g., a call) between two `Node`s, with associated weights.
    * `EdgeMap`: A slice of `Edge` pointers, likely representing incoming or outgoing edges for a `Node`.

4. **Analyze Core Functions:** Look for functions that perform significant actions:
    * `NewGraph(prof *Profile, o *Options) *Graph`: This is the primary function for creating the graph. It takes a `Profile` (presumably from a pprof file) and `Options`. This is a strong indicator of the package's main purpose.
    * `CreateNodes(prof *Profile, o *Options) (Nodes, locationMap)`: Called by `NewGraph`, this suggests the process of extracting and creating individual nodes from the profile data.
    * Methods on `Node` (`FlatValue`, `CumValue`, `AddToEdge`, `AddToEdgeDiv`, `addSample`): These indicate how node-specific data is accessed and manipulated. The "Flat" and "Cum" prefixes are common in profiling, referring to exclusive and inclusive metrics.
    * Methods on `Edge` (`WeightValue`):  Accessing edge weights.
    * Methods on `NodeMap` (`FindOrInsertNode`, `findOrInsertLine`): Managing the creation and retrieval of nodes, ensuring uniqueness.

5. **Infer Functionality and Purpose:** Based on the data structures and functions, start connecting the dots:
    * The package's primary function is to transform profiling data (likely from a `pprof` file, although the `Profile` type isn't defined in this snippet) into a graph representation.
    * `Node`s represent locations in the code, and `Edge`s represent relationships between them (e.g., function calls).
    * The `Options` struct allows customization of graph construction, such as defining how sample values are aggregated and which nodes to keep.
    * The `NodeMap` is used to efficiently merge data from different profile samples that refer to the same code location.
    * The graph structure is designed for visualization or further analysis of performance data.

6. **Consider Use Cases (and provide Go code examples):** Think about how such a graph might be used in practice:
    * **Call Graph Visualization:** The `In` and `Out` edges strongly suggest this. Example: Showing which functions call which other functions.
    * **Identifying Performance Bottlenecks:** Nodes with high `Cum` values (inclusive cost) are likely candidates for optimization.
    * **Understanding Program Flow:** The graph visually represents the execution path of the program.

7. **Address Command-Line Arguments and Assumptions:**  Since the code is part of an internal package, it's unlikely to directly handle command-line arguments. The `Options` struct suggests that the *caller* of this package would likely parse command-line flags and configure these options. It's important to make this assumption explicit.

8. **Identify Potential Pitfalls:** Think about common mistakes users might make when interacting with such a library (even if indirectly):
    * **Incorrect `SampleValue` or `SampleMeanDivisor`:** Choosing the wrong function to interpret sample data can lead to a meaningless graph.
    * **Misunderstanding `DropNegative`:**  Not realizing that this option might hide important performance issues if negative values are significant.
    * **Over-reliance on Default Options:**  Not understanding the impact of different options on the resulting graph.

9. **Structure the Answer:**  Organize the information logically using the requested format:
    * List the functionalities clearly.
    * Provide Go code examples illustrating key use cases.
    * Explain any assumptions made (e.g., about the input `Profile`).
    * Describe how command-line arguments *might* be handled by the *user* of this package.
    * Point out potential pitfalls.

10. **Refine and Review:**  Read through the generated answer to ensure it's accurate, clear, and addresses all aspects of the prompt. Check for any ambiguities or missing information. For instance, initially, I might focus heavily on the graph structure, but then I'd realize the importance of the `Options` struct and how it influences the graph creation process. I'd also clarify the assumption about the `Profile` type and its origin (likely from the `runtime/pprof` package).
这个 `go/src/internal/profile/graph.go` 文件定义了用于表示和操作性能剖析数据的有向图结构。它主要用于将 `pprof` (Go 语言的性能剖析工具) 生成的原始数据转换为更易于分析和可视化的图结构。

以下是其主要功能：

1. **定义图的基本元素：**
   - **`Node`:** 表示性能剖析报告中的一个节点，通常对应于程序中的一个特定位置（例如，一个函数、一行代码）。它包含以下信息：
     - `Info`:  `NodeInfo` 结构，包含节点的详细信息，如函数名、地址、行号等。
     - `Function`: 指向代表整个函数的 `Node` 的指针。这在子函数级别的剖析中很有用。
     - `Flat`, `FlatDiv`, `Cum`, `CumDiv`:  存储与该节点相关的性能指标值。`Flat` 是该节点独有的值，`Cum` 包含所有子节点的累积值。`Div` 后缀表示用于计算平均值的除数。
     - `In`, `Out`: `EdgeMap` 类型的切片，分别存储指向该节点的入边和从该节点发出的出边。
   - **`Edge`:** 表示图中节点之间的连接，通常代表函数调用关系。它包含以下信息：
     - `Src`, `Dest`: 指向边的源节点和目标节点的指针。
     - `Weight`, `WeightDiv`:  边的权重值和用于计算平均值的除数。权重可以表示调用次数、花费的时间等。
     - `Residual`:  布尔值，表示这条边是否是由于中间节点被移除而保留下来的“残余”边。
     - `Inline`: 布尔值，表示这条边是否代表一个内联调用。
   - **`Graph`:**  表示整个性能剖析图，包含一个 `Nodes` 切片，即图中所有节点的集合。

2. **提供创建图的机制：**
   - **`NewGraph(prof *Profile, o *Options) *Graph`:**  这是创建图的主要函数。它接收一个 `Profile` 类型的参数（假设该类型在其他地方定义，代表原始的性能剖析数据）和一个 `Options` 类型的参数，并返回一个 `Graph` 指针。
   - **`CreateNodes(prof *Profile, o *Options) (Nodes, locationMap)`:**  `NewGraph` 内部调用的函数，负责根据 `Profile` 中的 `Location` 信息创建 `Node` 对象。它还返回一个 `locationMap`，用于将 `Location` 的 ID 映射到对应的 `Node` 集合。

3. **支持配置图的创建行为：**
   - **`Options` 结构体:** 允许用户自定义图的创建方式，例如：
     - `SampleValue`:  一个函数，用于计算样本的实际值。不同的剖析类型可能有不同的样本值表示方式，这个选项允许用户指定如何从原始样本值中提取有意义的度量。
     - `SampleMeanDivisor`: 一个函数，用于计算平均图的除数。如果需要计算平均值，则需要提供此函数。
     - `DropNegative`:  一个布尔值，如果为 `true`，则会丢弃总值为负数的节点。
     - `KeptNodes`:  一个 `NodeSet`，如果非空，则只使用该集合中的节点创建图。

4. **提供操作图的方法：**
   - **`Node` 的方法:**
     - `FlatValue()`: 返回节点的独有值，如果提供了除数则计算平均值。
     - `CumValue()`: 返回节点的累积值，如果提供了除数则计算平均值。
     - `AddToEdge(to *Node, v int64, residual, inline bool)` 和 `AddToEdgeDiv(...)`: 用于在两个节点之间添加或更新边的权重。
   - **`EdgeMap` 的方法:**
     - `FindTo(n *Node) *Edge`:  查找指向特定节点的边。
     - `Add(e *Edge)`:  添加一条边。
     - `Delete(e *Edge)`: 删除一条边。
     - `Sort()`:  对边进行排序。
     - `Sum()`: 计算所有边的权重之和。

5. **提供辅助数据结构和方法：**
   - **`NodeInfo`:**  包含节点的名称、地址、起始行号和当前行号等信息。
   - **`NodeMap`:**  一个将 `NodeInfo` 映射到 `Node` 的 map，用于合并具有相同信息的报告条目。
   - **`NodeSet` 和 `NodePtrSet`:**  分别存储 `NodeInfo` 和 `Node` 指针的集合，用于过滤或标识节点。
   - **`locationMap`:**  用于将 `Location` 的 ID 映射到 `Node` 集合。

**它是什么go语言功能的实现？**

这个文件是 Go 语言 `pprof` 工具内部用于构建和操作性能剖析图的核心组件。`pprof` 工具读取性能剖析数据，然后使用这个 `graph` 包将数据组织成一个有向图，以便进行更深入的分析和可视化。例如，可以利用这个图来查找热点函数、分析调用关系、理解性能瓶颈等。

**Go 代码举例说明:**

假设我们已经有了一个 `Profile` 对象 `prof`，并且希望创建一个基于调用次数的性能剖析图。

```go
package main

import (
	"fmt"
	"internal/profile" // 假设 profile.go 文件与此代码在同一目录下
)

func main() {
	// 假设 prof 是通过某种方式加载的 pprof 数据
	prof := &profile.Profile{
		Sample: []*profile.Sample{
			{
				Location: []*profile.Location{
					{ID: 1},
					{ID: 2},
				},
				Value: []int64{1}, // 调用次数
			},
			{
				Location: []*profile.Location{
					{ID: 2},
					{ID: 3},
				},
				Value: []int64{2}, // 调用次数
			},
		},
		Location: []*profile.Location{
			{ID: 1, Address: 0x1000, Line: []profile.Line{{Function: &profile.Function{Name: "funcA"}}}},
			{ID: 2, Address: 0x2000, Line: []profile.Line{{Function: &profile.Function{Name: "funcB"}}}},
			{ID: 3, Address: 0x3000, Line: []profile.Line{{Function: &profile.Function{Name: "funcC"}}}},
		},
	}

	options := &profile.Options{
		SampleValue: func(s []int64) int64 {
			return s[0] // 使用第一个值作为样本值（调用次数）
		},
	}

	graph := profile.NewGraph(prof, options)

	fmt.Println(graph) // 打印图的字符串表示
}
```

**假设的输入与输出：**

**输入 (简化的 `prof` 对象):**

```
&profile.Profile{
  Sample: []*profile.Sample{
    {Location: []*profile.Location{ID: 1}, Value: []int64{1}},
    {Location: []*profile.Location{ID: 2}, Value: []int64{2}},
    {Location: []*profile.Location{ID: 1, ID: 2}, Value: []int64{3}},
    {Location: []*profile.Location{ID: 2, ID: 3}, Value: []int64{4}},
  },
  Location: []*profile.Location{
    {ID: 1, Address: 0x1000, Line: []profile.Line{{Function: &profile.Function{Name: "funcA"}}}},
    {ID: 2, Address: 0x2000, Line: []profile.Line{{Function: &profile.Function{Name: "funcB"}}}},
    {ID: 3, Address: 0x3000, Line: []profile.Line{{Function: &profile.Function{Name: "funcC"}}}},
  },
}
```

**输出 (可能的 `graph.String()` 输出):**

```
1: funcA[flat=1 cum=4]  -> [2]
2: funcB[flat=2 cum=7] [1] -> [3]
3: funcC[flat=0 cum=4] [2] ->
```

**解释:**

- 节点 1 代表 `funcA`，`flat=1` 表示 `funcA` 本身被直接调用了 1 次，`cum=4` 表示 `funcA` 及其调用的函数总共被调用了 4 次。 `-> [2]` 表示 `funcA` 调用了节点 2 (`funcB`)。
- 节点 2 代表 `funcB`，`flat=2` 表示 `funcB` 本身被直接调用了 2 次，`cum=7` 表示 `funcB` 及其调用的函数总共被调用了 7 次。 `[1] -> [3]` 表示 `funcB` 被节点 1 (`funcA`) 调用，并调用了节点 3 (`funcC`)。
- 节点 3 代表 `funcC`，`flat=0` 表示 `funcC` 本身没有被直接调用，`cum=4` 表示 `funcC` 被调用的总次数。 `[2] ->` 表示 `funcC` 被节点 2 (`funcB`) 调用。

**命令行参数的具体处理：**

这个 `graph.go` 文件本身**不直接处理命令行参数**。它的作用是根据已经加载的性能剖析数据和配置选项来构建图。

通常，`pprof` 工具或者使用这个 `graph` 包的其他工具会负责处理命令行参数。例如，`go tool pprof` 命令会接受诸如输入文件路径、报告类型、排序方式等参数。这些参数会被解析并用来配置如何加载和处理性能剖析数据，最终可能会影响传递给 `NewGraph` 函数的 `Options` 参数。

举个例子，`go tool pprof` 可能有以下相关的命令行参数（这只是示例，实际参数可能有所不同）：

- `-flat`:  指定报告按照 flat 值排序。这可能会影响 `Options.SampleValue` 的选择。
- `-cum`: 指定报告按照 cum 值排序。这也会影响 `Options.SampleValue` 的选择。
- `-mean`:  指示计算平均值。这可能会导致 `Options.SampleMeanDivisor` 被设置。
- `-trim`:  指定要保留的节点。这可能会影响 `Options.KeptNodes` 的设置。
- `-drop_negative`:  指定丢弃负值节点。这会设置 `Options.DropNegative` 为 `true`。

**使用者易犯错的点：**

1. **错误地理解 `SampleValue` 的作用：** 如果用户提供的 `SampleValue` 函数不能正确地从 `Sample.Value` 中提取期望的度量值（例如，将时间值误用为调用次数），则生成的图的含义会出错。

   ```go
   // 错误示例：假设样本值是纳秒，但用户将其直接用作调用次数
   options := &profile.Options{
       SampleValue: func(s []int64) int64 {
           return s[0] // 假设 s[0] 是纳秒
       },
   }
   ```

2. **不理解 `DropNegative` 的影响：**  如果性能剖析数据中存在具有负值的节点（例如，由于时间差计算导致），并且设置了 `DropNegative: true`，则这些节点会被完全移除，可能导致分析丢失一些信息。

3. **忽略 `SampleMeanDivisor` 的必要性：** 如果期望生成平均值相关的图，但没有提供正确的 `SampleMeanDivisor` 函数，则 `FlatValue()` 和 `CumValue()` 方法返回的平均值将不正确（除数为 0）。

4. **错误地使用 `KeptNodes` 进行过滤：** 如果 `KeptNodes` 设置不当，可能会过滤掉重要的节点，导致生成的图不完整或无法反映实际的性能状况。

总而言之，`go/src/internal/profile/graph.go` 提供了一个用于表示和操作性能剖析图的底层框架。理解其核心数据结构和方法，以及 `Options` 的作用，对于正确使用和分析 Go 程序的性能剖析数据至关重要。使用者需要根据具体的分析目标和性能剖析数据的特点，合理配置 `Options`，才能得到有意义的性能分析结果。

Prompt: 
```
这是路径为go/src/internal/profile/graph.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
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

// Package profile represents a pprof profile as a directed graph.
//
// This package is a simplified fork of github.com/google/pprof/internal/graph.
package profile

import (
	"fmt"
	"sort"
	"strings"
)

// Options encodes the options for constructing a graph
type Options struct {
	SampleValue       func(s []int64) int64 // Function to compute the value of a sample
	SampleMeanDivisor func(s []int64) int64 // Function to compute the divisor for mean graphs, or nil

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
}

// Graph summarizes a performance profile into a format that is
// suitable for visualization.
type Graph struct {
	Nodes Nodes
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
	if e := n.Out.FindTo(to); e != nil {
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
	n.Out.Add(info)
	to.In.Add(info)
}

// NodeInfo contains the attributes for a node.
type NodeInfo struct {
	Name              string
	Address           uint64
	StartLine, Lineno int
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
		// User requested line numbers, provide what we have.
		name = append(name, fmt.Sprintf(":%d", i.Lineno))
	case i.Name != "":
		// User requested function name. It was already included.
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
		Info: info,
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
	n.Function = nm.FindOrInsertNode(info, nil)
	return n
}

// EdgeMap is used to represent the incoming/outgoing edges from a node.
type EdgeMap []*Edge

func (em EdgeMap) FindTo(n *Node) *Edge {
	for _, e := range em {
		if e.Dest == n {
			return e
		}
	}
	return nil
}

func (em *EdgeMap) Add(e *Edge) {
	*em = append(*em, e)
}

func (em *EdgeMap) Delete(e *Edge) {
	for i, edge := range *em {
		if edge == e {
			(*em)[i] = (*em)[len(*em)-1]
			*em = (*em)[:len(*em)-1]
			return
		}
	}
}

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

// NewGraph computes a graph from a profile.
func NewGraph(prof *Profile, o *Options) *Graph {
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

		// Group the sample frames, based on a global map.
		// Count only the last two frames as a call edge. Frames higher up
		// the stack are unlikely to be repeated calls (e.g. runtime.main
		// calling main.main). So adding weights to call edges higher up
		// the stack may be not reflecting the actual call edge weights
		// in the program. Without a branch profile this is just an
		// approximation.
		i := 1
		if last := len(sample.Location) - 1; last < i {
			i = last
		}
		for ; i >= 0; i-- {
			l := sample.Location[i]
			locNodes := locationMap.get(l.ID)
			for ni := len(locNodes) - 1; ni >= 0; ni-- {
				n := locNodes[ni]
				if n == nil {
					residual = true
					continue
				}
				// Add cum weight to all nodes in stack, avoiding double counting.
				_, sawNode := seenNode[n]
				if !sawNode {
					seenNode[n] = true
					n.addSample(dw, w, false)
				}
				// Update edge weights for all edges in stack, avoiding double counting.
				if (!sawNode || !seenEdge[nodePair{n, parent}]) && parent != nil && n != parent {
					seenEdge[nodePair{n, parent}] = true
					parent.AddToEdgeDiv(n, dw, w, residual, ni != len(locNodes)-1)
				}

				parent = n
				residual = false
			}
		}
		if parent != nil && !residual {
			// Add flat weight to leaf node.
			parent.addSample(dw, w, true)
		}
	}

	return selectNodesForGraph(nodes, o.DropNegative)
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

type locationMap struct {
	s []Nodes          // a slice for small sequential IDs
	m map[uint64]Nodes // fallback for large IDs (unlikely)
}

func (l *locationMap) add(id uint64, n Nodes) {
	if id < uint64(len(l.s)) {
		l.s[id] = n
	} else {
		l.m[id] = n
	}
}

func (l locationMap) get(id uint64) Nodes {
	if id < uint64(len(l.s)) {
		return l.s[id]
	} else {
		return l.m[id]
	}
}

// CreateNodes creates graph nodes for all locations in a profile. It
// returns set of all nodes, plus a mapping of each location to the
// set of corresponding nodes (one per location.Line).
func CreateNodes(prof *Profile, o *Options) (Nodes, locationMap) {
	locations := locationMap{make([]Nodes, len(prof.Location)+1), make(map[uint64]Nodes)}
	nm := make(NodeMap, len(prof.Location))
	for _, l := range prof.Location {
		lines := l.Line
		if len(lines) == 0 {
			lines = []Line{{}} // Create empty line to include location info.
		}
		nodes := make(Nodes, len(lines))
		for ln := range lines {
			nodes[ln] = nm.findOrInsertLine(l, lines[ln], o)
		}
		locations.add(l.ID, nodes)
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

func (nm NodeMap) findOrInsertLine(l *Location, li Line, o *Options) *Node {
	var objfile string
	if m := l.Mapping; m != nil && m.File != "" {
		objfile = m.File
	}

	if ni := nodeInfo(l, li, objfile, o); ni != nil {
		return nm.FindOrInsertNode(*ni, o.KeptNodes)
	}
	return nil
}

func nodeInfo(l *Location, line Line, objfile string, o *Options) *NodeInfo {
	if line.Function == nil {
		return &NodeInfo{Address: l.Address}
	}
	ni := &NodeInfo{
		Address: l.Address,
		Lineno:  int(line.Line),
		Name:    line.Function.Name,
	}
	ni.StartLine = int(line.Function.StartLine)
	return ni
}

// Sum adds the flat and cum values of a set of nodes.
func (ns Nodes) Sum() (flat int64, cum int64) {
	for _, n := range ns {
		flat += n.Flat
		cum += n.Cum
	}
	return
}

func (n *Node) addSample(dw, w int64, flat bool) {
	// Update sample value
	if flat {
		n.FlatDiv += dw
		n.Flat += w
	} else {
		n.CumDiv += dw
		n.Cum += w
	}
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

// Sort returns a slice of the edges in the map, in a consistent
// order. The sort order is first based on the edge weight
// (higher-to-lower) and then by the node names to avoid flakiness.
func (em EdgeMap) Sort() []*Edge {
	el := make(edgeList, 0, len(em))
	for _, w := range em {
		el = append(el, w)
	}

	sort.Sort(el)
	return el
}

// Sum returns the total weight for a set of nodes.
func (em EdgeMap) Sum() int64 {
	var ret int64
	for _, edge := range em {
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

"""



```