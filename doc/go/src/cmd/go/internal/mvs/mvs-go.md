Response: Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Understanding: Context and Purpose**

The first line `// Package mvs implements Minimal Version Selection.` immediately tells us the core function of this code. The link to `https://research.swtch.com/vgo-mvs` reinforces this and points to the underlying algorithm being implemented. The file path `go/src/cmd/go/internal/mvs/mvs.go` places it within the Go toolchain, specifically in the module version selection logic.

**2. Deconstructing the Code: Identifying Key Components**

I started by identifying the major types and functions:

* **Interfaces:** `Reqs`, `UpgradeReqs`, `DowngradeReqs`. These define contracts for interacting with the module graph. The comments explain the purpose of each method (`Required`, `Max`, `Upgrade`, `Previous`). The hierarchical nature (Upgrade/Downgrade extending Reqs) is important.
* **Functions:** `BuildList`, `Req`, `UpgradeAll`, `Upgrade`, `Downgrade`. These are the main algorithms exposed by the package. The comments preceding each function give a high-level description of its purpose.
* **Helper Struct:** `override`. This seems to be a utility for temporarily modifying the dependency graph during specific operations.

**3. Analyzing Functionality (Method by Method):**

I went through each function and tried to understand its specific goal and how it achieves it. Here's a more detailed thought process for some key functions:

* **`BuildList`:** This is the core MVS algorithm. The comments explicitly mention the target module and the requirement graph. I noted the use of `par.Work` for parallel processing, suggesting optimization for network latency. The logic involving `g.Require` (implying a graph data structure), `upgrades`, and `errs` is crucial. The error handling section, particularly `g.FindPath`, suggests a need to provide useful error messages. The final assertion about `targets` ensures the target modules are included in the result.

* **`Req`:** The name "Req" suggests finding requirements. The comment about "minimal requirement list" and the `base` parameter gives clues. The code iterates through the `BuildList` result, calculates a postorder traversal of the dependency graph, and then uses this postorder to determine the minimal set of requirements, ensuring the `base` modules are included.

* **`UpgradeAll`:**  The name and comment are quite clear. It leverages `buildList` and passes an `upgrade` function that simply calls `reqs.Upgrade`.

* **`Upgrade`:**  This is more nuanced. It takes specific modules to upgrade. The code first checks existing requirements, then adds the upgrade targets if they aren't already there. It uses the `override` struct to temporarily modify the dependency information. The `upgradeTo` map handles potential conflicts when multiple upgrades are specified for the same module.

* **`Downgrade`:** This is the most complex function. The initial comment linking to the MVS paper is important. The code attempts to downgrade specified modules. The logic involving `added`, `rdeps`, `excluded`, and the `exclude`/`add` functions suggests a complex dependency tracking mechanism to avoid unintended side effects during downgrades. The fallback to using `BuildList` with an `override` towards the end is interesting and highlights the iterative nature of the downgrade process and the need to reconcile the requested downgrades with the overall dependency graph.

**4. Identifying Go Features and Examples:**

As I understood each function, I looked for opportunities to illustrate their functionality with Go code examples. This involved:

* **Thinking about typical use cases:** How would a developer use these functions?  For example, `BuildList` is fundamental, so I started there. `UpgradeAll` and `Upgrade` are common scenarios. `Downgrade` is more advanced.
* **Creating simple, illustrative scenarios:**  I didn't aim for complex examples, just enough to demonstrate the basic input and output. For `BuildList`, a simple dependency graph is sufficient. For `Upgrade`, specifying which modules to upgrade is key.
* **Using concrete types (even if simplified):** While the interfaces use `module.Version`, the examples could use simple structs with `Path` and `Version` for clarity. The `MockReqs` struct is a common pattern for testing and demonstrating interface usage.
* **Providing hypothetical inputs and outputs:**  This makes the examples more tangible and helps to understand the effect of the functions.

**5. Analyzing Command-Line Parameters (if applicable):**

I scanned the code for any direct interaction with command-line flags. Since this code is internal to the `go` command, it's likely used by other parts of the toolchain that *do* handle command-line arguments. Therefore, I pointed out that this specific code doesn't directly process them but is part of the larger process.

**6. Identifying Potential Pitfalls:**

For each function, I considered how a user might misuse it or encounter unexpected behavior.

* **`BuildList`:**  Misunderstanding the `Reqs` interface and providing incorrect `Max` logic is a key issue.
* **`Upgrade`:**  Specifying upgrades that conflict or are not compatible with the existing dependencies.
* **`Downgrade`:** The complexity of downgrading and potential for dependency conflicts makes this error-prone.

**7. Structuring the Answer:**

Finally, I organized my findings into the requested categories: Functionality, Go Feature Implementation (with examples), Command-Line Parameters, and Potential Pitfalls. This provides a clear and structured explanation of the code.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe I need to deeply understand the `par` package. **Correction:**  For this analysis, understanding that it's used for parallel execution is sufficient. The details of `par.Work` aren't strictly necessary to grasp the high-level functionality of MVS.
* **Initial thought:** The examples need to be fully runnable. **Correction:**  While runnable code is great, the primary goal of the examples here is illustration. Using simplified mock implementations of `Reqs` is acceptable for demonstrating the *concept*.
* **Realization:**  The `override` struct is a pattern for dependency injection or temporary modification, which is a valuable point to highlight.

By following these steps, focusing on understanding the purpose and interactions of the different components, and then illustrating with examples and potential issues, I could arrive at the comprehensive analysis provided in the initial prompt's answer.
这段代码是 Go 语言 `cmd/go` 工具中负责 **Minimal Version Selection (MVS)** 算法的核心实现。MVS 算法用于解决 Go 模块依赖管理中的版本选择问题，确保构建的可重复性和一致性。

**功能列表:**

1. **定义了描述模块依赖关系的接口 `Reqs`, `UpgradeReqs`, `DowngradeReqs`:**
   - `Reqs` 接口定义了获取模块显式依赖 (`Required`) 和比较版本 (`Max`) 的方法。
   - `UpgradeReqs` 接口继承自 `Reqs`，并增加了获取模块升级版本 (`Upgrade`) 的方法，用于 `go get -u` 等场景。
   - `DowngradeReqs` 接口继承自 `Reqs`，并增加了获取模块前一个版本 (`Previous`) 的方法，用于降级模块。

2. **实现了核心的 `BuildList` 函数:**
   - 该函数接收一组目标模块 (`targets`) 和一个实现了 `Reqs` 接口的对象。
   - 它遍历依赖图，为每个模块选择满足所有依赖且最高的版本。
   - 返回一个包含最终选定版本的模块列表，列表的第一个元素是目标模块自身，其余元素按模块路径排序。
   - 使用并行处理 (`par.Work`) 来加速依赖图的遍历，特别是当获取依赖信息涉及网络操作时。
   - 包含错误处理逻辑，当依赖解析出错时，会尝试找到从目标模块到错误模块的路径，以便提供更清晰的错误信息。

3. **实现了 `Req` 函数:**
   - 该函数用于计算目标模块的最小依赖列表，同时保证 `base` 参数中指定的模块必须出现在结果列表中。
   - 它首先调用 `BuildList` 获取完整的依赖列表。
   - 然后进行后序遍历，并根据依赖关系和 `base` 参数，筛选出最小的依赖集合。

4. **实现了 `UpgradeAll` 函数:**
   - 该函数将目标模块的所有依赖项升级到最新版本。
   - 它基于 `BuildList`，并提供一个升级函数，该函数会调用 `UpgradeReqs` 接口的 `Upgrade` 方法来获取每个依赖的最新版本。

5. **实现了 `Upgrade` 函数:**
   - 该函数允许指定要升级的特定模块。
   - 它首先获取目标模块的直接依赖。
   - 然后将要升级的模块添加到考虑范围，并可能覆盖已有的依赖版本。
   - 最终调用 `BuildList`，并传入一个升级函数，该函数会根据指定的升级列表来选择版本。

6. **实现了 `Downgrade` 函数:**
   - 该函数允许指定要降级的特定模块。
   - 它的实现较为复杂，需要考虑降级可能导致其他依赖项的不兼容。
   - 它首先尝试构建一个初步的降级列表，然后通过多次迭代和依赖分析，确保降级操作的正确性。
   - 它会处理由于降级导致的依赖冲突，并尝试找到合适的版本组合。

7. **定义了一个辅助结构体 `override`:**
   - 该结构体用于在 `Upgrade` 和 `Downgrade` 函数中临时修改模块的依赖关系，以便在 `BuildList` 过程中应用指定的升级或降级操作。

**它是什么 Go 语言功能的实现？**

这段代码是 Go 语言 **模块依赖管理** 功能的核心实现，具体来说是 **版本选择 (Version Selection)** 算法的实现。当你在 Go 项目中使用 `go get`, `go build`, `go mod tidy` 等命令时，这个 `mvs` 包就会发挥作用，帮助你确定项目中所有依赖模块应该使用的正确版本。

**Go 代码举例说明:**

假设我们有一个简单的 `Reqs` 接口的实现 `MockReqs`，它可以模拟模块的依赖关系和版本比较：

```go
package main

import (
	"fmt"
	"sort"

	"golang.org/x/mod/module"
	"go/src/cmd/go/internal/mvs"
)

type MockReqs struct {
	reqs map[module.Version][]module.Version
}

func (r *MockReqs) Required(m module.Version) ([]module.Version, error) {
	return r.reqs[m], nil
}

func (r *MockReqs) Max(path, v1, v2 string) string {
	if v1 == "none" {
		return v2
	}
	if v2 == "none" {
		return v1
	}
	if v1 > v2 { // 假设版本字符串可以直接比较大小
		return v1
	}
	return v2
}

func main() {
	reqs := &MockReqs{
		reqs: map[module.Version][]module.Version{
			{Path: "a", Version: "1.0.0"}: {
				{Path: "b", Version: "1.1.0"},
				{Path: "c", Version: "1.0.0"},
			},
			{Path: "b", Version: "1.1.0"}: {
				{Path: "c", Version: "1.1.0"},
			},
		},
	}

	target := module.Version{Path: "a", Version: "1.0.0"}
	buildList, err := mvs.BuildList([]module.Version{target}, reqs)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Build List:")
	for _, m := range buildList {
		fmt.Printf("%s@%s\n", m.Path, m.Version)
	}

	sort.Slice(buildList[1:], func(i, j int) bool {
		return buildList[i+1].Path < buildList[j+1].Path
	})

	fmt.Println("\nBuild List (sorted):")
	for _, m := range buildList {
		fmt.Printf("%s@%s\n", m.Path, m.Version)
	}
}
```

**假设的输入与输出:**

在这个例子中，`MockReqs` 定义了以下依赖关系：

- 模块 `a@1.0.0` 依赖 `b@1.1.0` 和 `c@1.0.0`
- 模块 `b@1.1.0` 依赖 `c@1.1.0`

**输入:**

```
target := module.Version{Path: "a", Version: "1.0.0"}
```

**输出:**

```
Build List:
a@1.0.0
c@1.1.0
b@1.1.0

Build List (sorted):
a@1.0.0
b@1.1.0
c@1.1.0
```

**代码推理:**

- `BuildList` 函数从目标模块 `a@1.0.0` 开始遍历依赖图。
- 它首先获取 `a@1.0.0` 的依赖：`b@1.1.0` 和 `c@1.0.0`。
- 然后获取 `b@1.1.0` 的依赖：`c@1.1.0`。
- 对于模块 `c`，存在两个版本要求：`1.0.0` (来自 `a`) 和 `1.1.0` (来自 `b`)。
- `Max` 函数会选择较高的版本，即 `1.1.0`。
- 最终的构建列表包含 `a@1.0.0`, `b@1.1.0`, 和 `c@1.1.0`。

**命令行参数的具体处理:**

这段代码本身 **不直接** 处理命令行参数。它是 `cmd/go` 工具内部的一个模块。`cmd/go` 工具会解析命令行参数（例如 `go get -u package` 中的 `-u`），然后根据这些参数调用 `mvs` 包中的相应函数。

例如，当执行 `go get -u example.com/foo` 时：

1. `cmd/go` 会解析 `-u` 参数，知道这是一个升级操作。
2. 它会创建一个实现了 `UpgradeReqs` 接口的对象，该对象可以从网络或本地缓存获取模块信息。
3. 它会调用 `mvs.UpgradeAll` 或 `mvs.Upgrade` 函数，并将目标模块 `example.com/foo` 和 `UpgradeReqs` 对象传递给它。
4. `mvs` 包中的函数会根据 `UpgradeReqs` 提供的信息和 MVS 算法，计算出需要升级的模块版本。
5. `cmd/go` 最终会根据 `mvs` 的结果，下载或更新相应的模块。

**使用者易犯错的点:**

虽然用户不直接与 `mvs` 包交互，但理解 MVS 的原理对于避免一些常见的模块依赖问题至关重要。一些容易犯错的点包括：

1. **对 `replace` 指令的误解:**  `go.mod` 文件中的 `replace` 指令会直接影响依赖图，可能导致 MVS 选择非预期的版本。用户需要理解 `replace` 的作用域和影响。

2. **对 `exclude` 指令的误解:**  `exclude` 指令会阻止 MVS 选择特定的模块版本，用户需要清楚排除某个版本可能会导致其他依赖项无法满足。

3. **手动修改 `go.mod` 文件引起的冲突:**  直接编辑 `go.mod` 文件而不理解 MVS 的工作方式，可能会引入不一致的依赖关系，导致构建失败。

4. **不理解 MVS 的最小版本选择原则:**  MVS 倾向于选择满足所有依赖的最低版本。如果用户期望使用某个模块的最新特性，可能需要显式地升级该模块。

**示例 - 误解 `replace` 指令:**

假设 `go.mod` 文件中有以下 `replace` 指令：

```
replace example.com/old => example.com/new v1.0.0
```

如果你的项目依赖的某个模块 `A` 依赖 `example.com/old` 的 `v1.1.0` 版本，而你使用了上述 `replace` 指令，MVS 会将对 `example.com/old` 的依赖替换为 `example.com/new@v1.0.0`。如果 `example.com/new@v1.0.0` 不提供 `A` 所期望的功能，可能会导致编译错误或运行时问题。

总而言之，这段代码是 Go 模块依赖管理的核心，它通过实现 MVS 算法，确保项目依赖的版本选择是可预测和一致的。理解其功能对于更好地管理 Go 项目的依赖至关重要。

### 提示词
```
这是路径为go/src/cmd/go/internal/mvs/mvs.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```go
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package mvs implements Minimal Version Selection.
// See https://research.swtch.com/vgo-mvs.
package mvs

import (
	"fmt"
	"slices"
	"sort"
	"sync"

	"cmd/internal/par"

	"golang.org/x/mod/module"
)

// A Reqs is the requirement graph on which Minimal Version Selection (MVS) operates.
//
// The version strings are opaque except for the special version "none"
// (see the documentation for module.Version). In particular, MVS does not
// assume that the version strings are semantic versions; instead, the Max method
// gives access to the comparison operation.
//
// It must be safe to call methods on a Reqs from multiple goroutines simultaneously.
// Because a Reqs may read the underlying graph from the network on demand,
// the MVS algorithms parallelize the traversal to overlap network delays.
type Reqs interface {
	// Required returns the module versions explicitly required by m itself.
	// The caller must not modify the returned list.
	Required(m module.Version) ([]module.Version, error)

	// Max returns the maximum of v1 and v2 (it returns either v1 or v2)
	// in the module with path p.
	//
	// For all versions v, Max(v, "none") must be v,
	// and for the target passed as the first argument to MVS functions,
	// Max(target, v) must be target.
	//
	// Note that v1 < v2 can be written Max(v1, v2) != v1
	// and similarly v1 <= v2 can be written Max(v1, v2) == v2.
	Max(p, v1, v2 string) string
}

// An UpgradeReqs is a Reqs that can also identify available upgrades.
type UpgradeReqs interface {
	Reqs

	// Upgrade returns the upgraded version of m,
	// for use during an UpgradeAll operation.
	// If m should be kept as is, Upgrade returns m.
	// If m is not yet used in the build, then m.Version will be "none".
	// More typically, m.Version will be the version required
	// by some other module in the build.
	//
	// If no module version is available for the given path,
	// Upgrade returns a non-nil error.
	// TODO(rsc): Upgrade must be able to return errors,
	// but should "no latest version" just return m instead?
	Upgrade(m module.Version) (module.Version, error)
}

// A DowngradeReqs is a Reqs that can also identify available downgrades.
type DowngradeReqs interface {
	Reqs

	// Previous returns the version of m.Path immediately prior to m.Version,
	// or "none" if no such version is known.
	Previous(m module.Version) (module.Version, error)
}

// BuildList returns the build list for the target module.
//
// target is the root vertex of a module requirement graph. For cmd/go, this is
// typically the main module, but note that this algorithm is not intended to
// be Go-specific: module paths and versions are treated as opaque values.
//
// reqs describes the module requirement graph and provides an opaque method
// for comparing versions.
//
// BuildList traverses the graph and returns a list containing the highest
// version for each visited module. The first element of the returned list is
// target itself; reqs.Max requires target.Version to compare higher than all
// other versions, so no other version can be selected. The remaining elements
// of the list are sorted by path.
//
// See https://research.swtch.com/vgo-mvs for details.
func BuildList(targets []module.Version, reqs Reqs) ([]module.Version, error) {
	return buildList(targets, reqs, nil)
}

func buildList(targets []module.Version, reqs Reqs, upgrade func(module.Version) (module.Version, error)) ([]module.Version, error) {
	cmp := func(p, v1, v2 string) int {
		if reqs.Max(p, v1, v2) != v1 {
			return -1
		}
		if reqs.Max(p, v2, v1) != v2 {
			return 1
		}
		return 0
	}

	var (
		mu       sync.Mutex
		g        = NewGraph(cmp, targets)
		upgrades = map[module.Version]module.Version{}
		errs     = map[module.Version]error{} // (non-nil errors only)
	)

	// Explore work graph in parallel in case reqs.Required
	// does high-latency network operations.
	var work par.Work[module.Version]
	for _, target := range targets {
		work.Add(target)
	}
	work.Do(10, func(m module.Version) {

		var required []module.Version
		var err error
		if m.Version != "none" {
			required, err = reqs.Required(m)
		}

		u := m
		if upgrade != nil {
			upgradeTo, upErr := upgrade(m)
			if upErr == nil {
				u = upgradeTo
			} else if err == nil {
				err = upErr
			}
		}

		mu.Lock()
		if err != nil {
			errs[m] = err
		}
		if u != m {
			upgrades[m] = u
			required = append([]module.Version{u}, required...)
		}
		g.Require(m, required)
		mu.Unlock()

		for _, r := range required {
			work.Add(r)
		}
	})

	// If there was an error, find the shortest path from the target to the
	// node where the error occurred so we can report a useful error message.
	if len(errs) > 0 {
		errPath := g.FindPath(func(m module.Version) bool {
			return errs[m] != nil
		})
		if len(errPath) == 0 {
			panic("internal error: could not reconstruct path to module with error")
		}

		err := errs[errPath[len(errPath)-1]]
		isUpgrade := func(from, to module.Version) bool {
			if u, ok := upgrades[from]; ok {
				return u == to
			}
			return false
		}
		return nil, NewBuildListError(err, errPath, isUpgrade)
	}

	// The final list is the minimum version of each module found in the graph.
	list := g.BuildList()
	if vs := list[:len(targets)]; !slices.Equal(vs, targets) {
		// target.Version will be "" for modload, the main client of MVS.
		// "" denotes the main module, which has no version. However, MVS treats
		// version strings as opaque, so "" is not a special value here.
		// See golang.org/issue/31491, golang.org/issue/29773.
		panic(fmt.Sprintf("mistake: chose versions %+v instead of targets %+v", vs, targets))
	}
	return list, nil
}

// Req returns the minimal requirement list for the target module,
// with the constraint that all module paths listed in base must
// appear in the returned list.
func Req(mainModule module.Version, base []string, reqs Reqs) ([]module.Version, error) {
	list, err := BuildList([]module.Version{mainModule}, reqs)
	if err != nil {
		return nil, err
	}

	// Note: Not running in parallel because we assume
	// that list came from a previous operation that paged
	// in all the requirements, so there's no I/O to overlap now.

	max := map[string]string{}
	for _, m := range list {
		max[m.Path] = m.Version
	}

	// Compute postorder, cache requirements.
	var postorder []module.Version
	reqCache := map[module.Version][]module.Version{}
	reqCache[mainModule] = nil

	var walk func(module.Version) error
	walk = func(m module.Version) error {
		_, ok := reqCache[m]
		if ok {
			return nil
		}
		required, err := reqs.Required(m)
		if err != nil {
			return err
		}
		reqCache[m] = required
		for _, m1 := range required {
			if err := walk(m1); err != nil {
				return err
			}
		}
		postorder = append(postorder, m)
		return nil
	}
	for _, m := range list {
		if err := walk(m); err != nil {
			return nil, err
		}
	}

	// Walk modules in reverse post-order, only adding those not implied already.
	have := map[module.Version]bool{}
	walk = func(m module.Version) error {
		if have[m] {
			return nil
		}
		have[m] = true
		for _, m1 := range reqCache[m] {
			walk(m1)
		}
		return nil
	}
	// First walk the base modules that must be listed.
	var min []module.Version
	haveBase := map[string]bool{}
	for _, path := range base {
		if haveBase[path] {
			continue
		}
		m := module.Version{Path: path, Version: max[path]}
		min = append(min, m)
		walk(m)
		haveBase[path] = true
	}
	// Now the reverse postorder to bring in anything else.
	for i := len(postorder) - 1; i >= 0; i-- {
		m := postorder[i]
		if max[m.Path] != m.Version {
			// Older version.
			continue
		}
		if !have[m] {
			min = append(min, m)
			walk(m)
		}
	}
	sort.Slice(min, func(i, j int) bool {
		return min[i].Path < min[j].Path
	})
	return min, nil
}

// UpgradeAll returns a build list for the target module
// in which every module is upgraded to its latest version.
func UpgradeAll(target module.Version, reqs UpgradeReqs) ([]module.Version, error) {
	return buildList([]module.Version{target}, reqs, func(m module.Version) (module.Version, error) {
		if m.Path == target.Path {
			return target, nil
		}

		return reqs.Upgrade(m)
	})
}

// Upgrade returns a build list for the target module
// in which the given additional modules are upgraded.
func Upgrade(target module.Version, reqs UpgradeReqs, upgrade ...module.Version) ([]module.Version, error) {
	list, err := reqs.Required(target)
	if err != nil {
		return nil, err
	}

	pathInList := make(map[string]bool, len(list))
	for _, m := range list {
		pathInList[m.Path] = true
	}
	list = append([]module.Version(nil), list...)

	upgradeTo := make(map[string]string, len(upgrade))
	for _, u := range upgrade {
		if !pathInList[u.Path] {
			list = append(list, module.Version{Path: u.Path, Version: "none"})
		}
		if prev, dup := upgradeTo[u.Path]; dup {
			upgradeTo[u.Path] = reqs.Max(u.Path, prev, u.Version)
		} else {
			upgradeTo[u.Path] = u.Version
		}
	}

	return buildList([]module.Version{target}, &override{target, list, reqs}, func(m module.Version) (module.Version, error) {
		if v, ok := upgradeTo[m.Path]; ok {
			return module.Version{Path: m.Path, Version: v}, nil
		}
		return m, nil
	})
}

// Downgrade returns a build list for the target module
// in which the given additional modules are downgraded,
// potentially overriding the requirements of the target.
//
// The versions to be downgraded may be unreachable from reqs.Latest and
// reqs.Previous, but the methods of reqs must otherwise handle such versions
// correctly.
func Downgrade(target module.Version, reqs DowngradeReqs, downgrade ...module.Version) ([]module.Version, error) {
	// Per https://research.swtch.com/vgo-mvs#algorithm_4:
	// “To avoid an unnecessary downgrade to E 1.1, we must also add a new
	// requirement on E 1.2. We can apply Algorithm R to find the minimal set of
	// new requirements to write to go.mod.”
	//
	// In order to generate those new requirements, we need to identify versions
	// for every module in the build list — not just reqs.Required(target).
	list, err := BuildList([]module.Version{target}, reqs)
	if err != nil {
		return nil, err
	}
	list = list[1:] // remove target

	max := make(map[string]string)
	for _, r := range list {
		max[r.Path] = r.Version
	}
	for _, d := range downgrade {
		if v, ok := max[d.Path]; !ok || reqs.Max(d.Path, v, d.Version) != d.Version {
			max[d.Path] = d.Version
		}
	}

	var (
		added    = make(map[module.Version]bool)
		rdeps    = make(map[module.Version][]module.Version)
		excluded = make(map[module.Version]bool)
	)
	var exclude func(module.Version)
	exclude = func(m module.Version) {
		if excluded[m] {
			return
		}
		excluded[m] = true
		for _, p := range rdeps[m] {
			exclude(p)
		}
	}
	var add func(module.Version)
	add = func(m module.Version) {
		if added[m] {
			return
		}
		added[m] = true
		if v, ok := max[m.Path]; ok && reqs.Max(m.Path, m.Version, v) != v {
			// m would upgrade an existing dependency — it is not a strict downgrade,
			// and because it was already present as a dependency, it could affect the
			// behavior of other relevant packages.
			exclude(m)
			return
		}
		list, err := reqs.Required(m)
		if err != nil {
			// If we can't load the requirements, we couldn't load the go.mod file.
			// There are a number of reasons this can happen, but this usually
			// means an older version of the module had a missing or invalid
			// go.mod file. For example, if example.com/mod released v2.0.0 before
			// migrating to modules (v2.0.0+incompatible), then added a valid go.mod
			// in v2.0.1, downgrading from v2.0.1 would cause this error.
			//
			// TODO(golang.org/issue/31730, golang.org/issue/30134): if the error
			// is transient (we couldn't download go.mod), return the error from
			// Downgrade. Currently, we can't tell what kind of error it is.
			exclude(m)
			return
		}
		for _, r := range list {
			add(r)
			if excluded[r] {
				exclude(m)
				return
			}
			rdeps[r] = append(rdeps[r], m)
		}
	}

	downgraded := make([]module.Version, 0, len(list)+1)
	downgraded = append(downgraded, target)
List:
	for _, r := range list {
		add(r)
		for excluded[r] {
			p, err := reqs.Previous(r)
			if err != nil {
				// This is likely a transient error reaching the repository,
				// rather than a permanent error with the retrieved version.
				//
				// TODO(golang.org/issue/31730, golang.org/issue/30134):
				// decode what to do based on the actual error.
				return nil, err
			}
			// If the target version is a pseudo-version, it may not be
			// included when iterating over prior versions using reqs.Previous.
			// Insert it into the right place in the iteration.
			// If v is excluded, p should be returned again by reqs.Previous on the next iteration.
			if v := max[r.Path]; reqs.Max(r.Path, v, r.Version) != v && reqs.Max(r.Path, p.Version, v) != p.Version {
				p.Version = v
			}
			if p.Version == "none" {
				continue List
			}
			add(p)
			r = p
		}
		downgraded = append(downgraded, r)
	}

	// The downgrades we computed above only downgrade to versions enumerated by
	// reqs.Previous. However, reqs.Previous omits some versions — such as
	// pseudo-versions and retracted versions — that may be selected as transitive
	// requirements of other modules.
	//
	// If one of those requirements pulls the version back up above the version
	// identified by reqs.Previous, then the transitive dependencies of that
	// initially-downgraded version should no longer matter — in particular, we
	// should not add new dependencies on module paths that nothing else in the
	// updated module graph even requires.
	//
	// In order to eliminate those spurious dependencies, we recompute the build
	// list with the actual versions of the downgraded modules as selected by MVS,
	// instead of our initial downgrades.
	// (See the downhiddenartifact and downhiddencross test cases).
	actual, err := BuildList([]module.Version{target}, &override{
		target: target,
		list:   downgraded,
		Reqs:   reqs,
	})
	if err != nil {
		return nil, err
	}
	actualVersion := make(map[string]string, len(actual))
	for _, m := range actual {
		actualVersion[m.Path] = m.Version
	}

	downgraded = downgraded[:0]
	for _, m := range list {
		if v, ok := actualVersion[m.Path]; ok {
			downgraded = append(downgraded, module.Version{Path: m.Path, Version: v})
		}
	}

	return BuildList([]module.Version{target}, &override{
		target: target,
		list:   downgraded,
		Reqs:   reqs,
	})
}

type override struct {
	target module.Version
	list   []module.Version
	Reqs
}

func (r *override) Required(m module.Version) ([]module.Version, error) {
	if m == r.target {
		return r.list, nil
	}
	return r.Reqs.Required(m)
}
```