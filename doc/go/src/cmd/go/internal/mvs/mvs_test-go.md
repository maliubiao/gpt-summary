Response: Let's break down the thought process for analyzing this Go test file.

**1. Initial Scan and High-Level Understanding:**

* **Filename:** `mvs_test.go` suggests it's testing something related to "MVS". Given the package name `mvs`, this reinforces that idea. The location `go/src/cmd/go/internal/mvs/` indicates it's an internal part of the Go toolchain, specifically within the `go` command.
* **Copyright and License:** Standard Go boilerplate, indicating the source and licensing.
* **Imports:**  `fmt`, `reflect`, `strings`, and `testing` are standard testing imports. The crucial one is `golang.org/x/mod/module`, pointing to functionality for dealing with Go modules. This strongly hints that "MVS" is related to module version selection.
* **Global Variable `tests`:** This is a large string literal. The format with `name:`, `A:`, `build A:`, etc., strongly suggests a declarative test setup. Each section likely represents a test case with different scenarios.

**2. Deeper Dive into the `tests` String:**

* **Pattern Recognition:** The structure within `tests` is consistent. Lines starting with a capital letter (e.g., `A: B1 C2`) likely define module dependencies. Lines starting with keywords like `build`, `upgrade`, `downgrade`, and `req` are test actions.
* **Interpreting the Keywords:**
    * `name`: Clearly the name of the test scenario.
    * `A: B1 C2`: Seems like module `A` depends on `B1` and `C2`. The numbers likely represent versions.
    * `build A: A B1 C2 D4 E2 F1`:  This looks like testing the result of a build operation for module `A`. The output lists the selected versions of all involved modules.
    * `upgrade`, `downgrade`:  Suggest testing the module version upgrade and downgrade functionalities. The `*` likely signifies upgrading all dependencies.
    * `req`:  Probably related to "requirements" – perhaps finding the minimal set of required modules.

**3. Analyzing the `Test` Function:**

* **Test Structure:**  The `Test` function iterates through the lines of the `tests` string. It parses each line based on the keywords identified earlier.
* **`flush` Function:** This function executes the accumulated test functions (`fns`) for a given `name`. This confirms the grouping of test actions under a scenario name.
* **`m` and `ms` Functions:** These are helper functions to create `module.Version` objects from string representations. This solidifies the connection to Go modules.
* **`checkList` Function:**  This function compares the actual output of a test action with the expected output defined in the `tests` string. It uses `reflect.DeepEqual` for accurate comparison.
* **Switch Statement:** The `switch kf[0]` handles different test actions based on the first word of the key. This confirms the interpretation of the keywords.
* **Dependency Mapping:** The `if len(kf) == 1 && 'A' <= key[0] && key[0] <= 'Z'` block is responsible for building the dependency graph (`reqs`).

**4. Examining `reqsMap` and its Methods:**

* **`reqsMap` Type:**  A `map[module.Version][]module.Version`, representing the dependency graph. The key is a module, and the value is a list of its direct dependencies.
* **`Max` Method:**  Compares two versions and returns the later one. The "none" handling is interesting and likely represents the absence of a version.
* **`Upgrade` Method:** Finds the latest non-hidden version of a given module within the `reqsMap`. This confirms the suspicion that `reqsMap` holds information about available module versions.
* **`Previous` Method:** Finds the latest non-hidden version *older* than the given module. This is crucial for downgrade functionality.
* **`Required` Method:**  Returns the direct dependencies of a given module from the `reqsMap`.

**5. Connecting the Pieces and Formulating the Explanation:**

* **Central Purpose:** The code is testing the "Minimum Version Selection" (MVS) algorithm within the Go module system. This algorithm determines the specific versions of dependencies to use when building a Go project.
* **Test Scenarios:** Each scenario in the `tests` string sets up a dependency graph and then tests different MVS operations (build, upgrade, downgrade, requirement minimization).
* **Code Examples:**  Demonstrate how the test scenarios translate to potential real-world Go module configurations. Show how `go get` might trigger these MVS calculations.
* **Command-Line Arguments:** Explain how `go get` and its flags relate to the tested operations (e.g., specifying a version for upgrade/downgrade).
* **Common Mistakes:** Highlight potential pitfalls users might encounter, such as unexpected version selections during upgrades or downgrades, or issues with cyclic dependencies.

**Self-Correction/Refinement during the Process:**

* Initially, the role of `reqsMap` might not be immediately obvious. However, observing how it's populated in the `Test` function and used in the MVS functions clarifies that it represents the *universe* of available module versions and their declared dependencies for the test scenario.
* The `.hidden` suffix on some versions becomes meaningful when examining the `Upgrade` and `Previous` methods. It indicates a mechanism to exclude certain versions from automatic selection.
* Understanding the purpose of each test case within the `tests` string requires careful examination of the input dependencies and the expected output. This often involves mentally tracing the MVS algorithm's steps.

By following these steps, combining observation, deduction, and knowledge of Go modules, we can arrive at a comprehensive understanding of the provided test code.
这段代码是 Go 语言 `cmd/go` 工具中用于测试 **Minimum Version Selection (MVS)** 算法实现的一部分。MVS 是 Go Modules 的核心机制，用于确定项目依赖的最佳版本。

**功能列表:**

1. **定义测试用例:**  通过字符串 `tests` 定义了一系列测试场景，每个场景模拟了不同的模块依赖关系和操作。
2. **模拟模块依赖关系:**  每个测试用例中，形如 `A: B1 C2` 的行定义了模块 `A` 依赖于模块 `B` 的版本 `1` 和模块 `C` 的版本 `2`。
3. **测试构建 (build) 操作:**  `build A: A B1 C2 D4 E2 F1` 测试在给定依赖关系下，构建模块 `A` 时 MVS 算法选择的最终依赖版本列表。
4. **测试升级 (upgrade) 操作:**
   - `upgrade* A: A B1 C4 D5 E2 F1 G1` 测试将模块 `A` 的所有依赖升级到最新版本时 MVS 算法的选择。
   - `upgrade A C4: A B1 C4 D4 E2 F1 G1` 测试将模块 `A` 的某个特定依赖（这里是 `C`) 升级到指定版本 (`C4`) 时 MVS 算法的选择。
   - `upgradereq A B2: B2 E2` 测试升级 `A` 的依赖 `B` 到 `B2` 后，计算 `B2` 的最小依赖列表。
5. **测试降级 (downgrade) 操作:** `downgrade A2 D2: A2 C4 D2 E2 F1 G1` 测试将模块 `A2` 的某个依赖（这里是 `D`) 降级到指定版本 (`D2`) 时 MVS 算法的选择。
6. **测试需求 (req) 操作 (Requirement Minimization):**  `req A:   B1    D1` 测试在构建模块 `A` 的基础上，为了满足 `A` 的需求，需要包含的最小依赖集合。
7. **辅助函数:**
   - `m(s string) module.Version`: 将形如 "A1" 的字符串转换为 `module.Version` 结构体。
   - `ms(list []string) []module.Version`: 将字符串切片转换为 `module.Version` 结构体切片。
   - `checkList(...)`: 用于比较实际的构建/升级/降级结果与预期结果是否一致。
8. **`reqsMap` 类型:**  一个 map，用于存储模块及其依赖关系，模拟模块仓库。
9. **`reqsMap` 的方法:**
   - `Max(path, v1, v2 string) string`: 返回两个版本号中较新的一个。
   - `Upgrade(m module.Version) (module.Version, error)`:  返回给定模块路径的最新非隐藏版本。
   - `Previous(m module.Version) (module.Version, error)`: 返回给定模块路径的次新非隐藏版本。
   - `Required(m module.Version) ([]module.Version, error)`: 返回给定模块的直接依赖列表。

**Go 语言功能实现推断：Go Modules 的版本选择机制 (MVS)**

这段代码的核心目标是测试 Go Modules 中用于解决依赖冲突和选择合适依赖版本的 MVS 算法。

**Go 代码举例说明:**

假设我们有以下 `go.mod` 文件：

```go
module example.com/myproject

go 1.16

require (
	example.com/A v1.0.0
)
```

并且 `example.com/A` 的 `go.mod` 文件如下：

```go
module example.com/A

go 1.16

require (
	example.com/B v1.1.0
	example.com/C v1.2.0
)
```

同时，`example.com/B` 和 `example.com/C` 也可能依赖于其他模块的不同版本。

当执行 `go build` 或 `go mod tidy` 时，Go 工具会使用 MVS 算法来确定最终使用的 `B` 和 `C` 的版本，即使它们可能在其他依赖中被请求了不同的版本。

**假设的输入与输出 (对应 `build A` 测试用例):**

假设 `reqsMap` 中包含了 `A`, `B`, `C`, `D`, `E`, `F`, `G` 等模块的不同版本及其依赖关系，如同 `tests` 字符串中 `name: blog` 部分定义的那样。

**输入:**

```go
target := module.Version{Path: "A"}
reqs := reqsMap{
	module.Version{Path: "A"}: []module.Version{{Path: "B", Version: "1"}, {Path: "C", Version: "2"}},
	module.Version{Path: "B", Version: "1"}: []module.Version{{Path: "D", Version: "3"}},
	module.Version{Path: "C", Version: "1"}: []module.Version{{Path: "D", Version: "2"}},
	module.Version{Path: "C", Version: "2"}: []module.Version{{Path: "D", Version: "4"}},
	// ... 其他模块的版本和依赖
}
```

**输出 (对应 `build A:       A B1 C2 D4 E2 F1`):**

```go
buildList, err := BuildList([]module.Version{target}, reqs)
// buildList 的值将会是:
// []module.Version{
// 	{Path: "A"},
// 	{Path: "B", Version: "1"},
// 	{Path: "C", Version: "2"},
// 	{Path: "D", Version: "4"},
// 	{Path: "E", Version: "2"},
// 	{Path: "F", Version: "1"},
// }
```

**命令行参数的具体处理:**

虽然这段代码本身没有直接处理命令行参数，但它测试的 MVS 算法是 `go` 命令（如 `go get`, `go build`, `go mod tidy` 等）的核心组成部分。

* **`go get <module>@<version>`:**  这个命令会指示 Go 工具升级或降级指定的模块到特定版本。例如，`go get example.com/C@v1.4.0` 可能会触发 `upgrade` 相关的 MVS 逻辑。
* **`go build`:**  在构建项目时，如果 `go.mod` 文件中有新的依赖或依赖关系发生变化，`go build` 会隐式地运行 MVS 算法来选择合适的依赖版本。
* **`go mod tidy`:**  这个命令会清理 `go.mod` 文件，移除不再需要的依赖，并确保依赖关系是最新的。它也会使用 MVS 算法来确定最终的依赖版本。

**使用者易犯错的点 (基于测试用例推理):**

1. **意外的依赖版本升级/降级:**  例如，在 `name: blog` 的 `upgrade* A` 测试中，虽然只升级了 `A`，但由于 MVS 算法的特性，`C` 从 `C2` 升级到了 `C4`，并且引入了新的依赖 `G1`。用户可能只期望升级 `A` 本身，而没有预料到传递性依赖的变化。
2. **循环依赖处理不当:**  `name: cycle1`, `cycle2`, `cycle3` 等测试用例涉及到循环依赖。用户在设计模块依赖关系时，如果引入循环依赖，MVS 算法会尝试找到一个合理的解决方案，但有时可能会导致选择了非预期的版本。
3. **对 `upgrade` 和 `downgrade` 的理解偏差:** `downcross1` 测试用例说明了降级操作的限制。降级操作主要移除需求，而不是像升级那样同时添加新的需求。用户可能期望通过降级一个模块来引入另一个模块的旧版本，但这可能不会按预期工作。
4. **对隐藏版本的影响理解不足:**  带有 `.hidden` 后缀的版本在某些操作中会被忽略，例如在 `up1` 和 `up2` 测试用例中，升级操作会跳过隐藏版本。用户可能需要理解隐藏版本在 MVS 算法中的特殊处理方式。

总而言之，这段代码是 Go Modules 版本选择机制的单元测试，通过模拟各种依赖场景和操作，验证 MVS 算法的正确性和健壮性。理解这些测试用例可以帮助开发者更好地理解 Go Modules 的工作原理，并避免在使用过程中出现一些常见的错误。

### 提示词
```
这是路径为go/src/cmd/go/internal/mvs/mvs_test.go的go语言实现的一部分， 请列举一下它的功能, 　
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

package mvs

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/mod/module"
)

var tests = `
# Scenario from blog.
name: blog
A: B1 C2
B1: D3
C1: D2
C2: D4
C3: D5
C4: G1
D2: E1
D3: E2
D4: E2 F1
D5: E2
G1: C4
A2: B1 C4 D4
build A:       A B1 C2 D4 E2 F1
upgrade* A:    A B1 C4 D5 E2 F1 G1
upgrade A C4:  A B1 C4 D4 E2 F1 G1
build A2:     A2 B1 C4 D4 E2 F1 G1
downgrade A2 D2: A2 C4 D2 E2 F1 G1

name: trim
A: B1 C2
B1: D3
C2: B2
B2:
build A: A B2 C2 D3

# Cross-dependency between D and E.
# No matter how it arises, should get result of merging all build lists via max,
# which leads to including both D2 and E2.

name: cross1
A: B C
B: D1
C: D2
D1: E2
D2: E1
build A: A B C D2 E2

name: cross1V
A: B2 C D2 E1
B1:
B2: D1
C: D2
D1: E2
D2: E1
build A: A B2 C D2 E2

name: cross1U
A: B1 C
B1:
B2: D1
C: D2
D1: E2
D2: E1
build A:      A B1 C D2 E1
upgrade A B2: A B2 C D2 E2

name: cross1R
A: B C
B: D2
C: D1
D1: E2
D2: E1
build A: A B C D2 E2

name: cross1X
A: B C
B: D1 E2
C: D2
D1: E2
D2: E1
build A: A B C D2 E2

name: cross2
A: B D2
B: D1
D1: E2
D2: E1
build A: A B D2 E2

name: cross2X
A: B D2
B: D1 E2
C: D2
D1: E2
D2: E1
build A: A B D2 E2

name: cross3
A: B D2 E1
B: D1
D1: E2
D2: E1
build A: A B D2 E2

name: cross3X
A: B D2 E1
B: D1 E2
D1: E2
D2: E1
build A: A B D2 E2

# Should not get E2 here, because B has been updated
# not to depend on D1 anymore.
name: cross4
A1: B1 D2
A2: B2 D2
B1: D1
B2: D2
D1: E2
D2: E1
build A1: A1 B1 D2 E2
build A2: A2 B2 D2 E1

# But the upgrade from A1 preserves the E2 dep explicitly.
upgrade A1 B2: A1 B2 D2 E2
upgradereq A1 B2: B2 E2

name: cross5
A: D1
D1: E2
D2: E1
build A:       A D1 E2
upgrade* A:    A D2 E2
upgrade A D2:  A D2 E2
upgradereq A D2: D2 E2

name: cross6
A: D2
D1: E2
D2: E1
build A:      A D2 E1
upgrade* A:   A D2 E2
upgrade A E2: A D2 E2

name: cross7
A: B C
B: D1
C: E1
D1: E2
E1: D2
build A: A B C D2 E2

# golang.org/issue/31248:
# Even though we select X2, the requirement on I1
# via X1 should be preserved.
name: cross8
M: A1 B1
A1: X1
B1: X2
X1: I1
X2:
build M: M A1 B1 I1 X2

# Upgrade from B1 to B2 should not drop the transitive dep on D.
name: drop
A: B1 C1
B1: D1
B2:
C2:
D2:
build A:    A B1 C1 D1
upgrade* A: A B2 C2 D2

name: simplify
A: B1 C1
B1: C2
C1: D1
C2:
build A: A B1 C2 D1

name: up1
A: B1 C1
B1:
B2:
B3:
B4:
B5.hidden:
C2:
C3:
build A:    A B1 C1
upgrade* A: A B4 C3

name: up2
A: B5.hidden C1
B1:
B2:
B3:
B4:
B5.hidden:
C2:
C3:
build A:    A B5.hidden C1
upgrade* A: A B5.hidden C3

name: down1
A: B2
B1: C1
B2: C2
build A:        A B2 C2
downgrade A C1: A B1 C1

name: down2
A: B2 E2
B1:
B2: C2 F2
C1:
D1:
C2: D2 E2
D2: B2
E2: D2
E1:
F1:
build A:        A B2 C2 D2 E2 F2
downgrade A F1: A B1 C1 D1 E1 F1

# https://research.swtch.com/vgo-mvs#algorithm_4:
# “[D]owngrades are constrained to only downgrade packages, not also upgrade
# them; if an upgrade before downgrade is needed, the user must ask for it
# explicitly.”
#
# Here, downgrading B2 to B1 upgrades C1 to C2, and C2 does not depend on D2.
# However, C2 would be an upgrade — not a downgrade — so B1 must also be
# rejected.
name: downcross1
A: B2 C1
B1: C2
B2: C1
C1: D2
C2:
D1:
D2:
build A:        A B2 C1 D2
downgrade A D1: A       D1

# https://research.swtch.com/vgo-mvs#algorithm_4:
# “Unlike upgrades, downgrades must work by removing requirements, not adding
# them.”
#
# However, downgrading a requirement may introduce a new requirement on a
# previously-unrequired module. If each dependency's requirements are complete
# (“tidy”), that can't change the behavior of any other package whose version is
# not also being downgraded, so we should allow it.
name: downcross2
A: B2
B1: C1
B2: D2
C1:
D1:
D2:
build A:        A B2    D2
downgrade A D1: A B1 C1 D1

name: downcycle
A: A B2
B2: A
B1:
build A:        A B2
downgrade A B1: A B1

# Both B3 and C2 require D2.
# If we downgrade D to D1, then in isolation B3 would downgrade to B1,
# because B2 is hidden — B1 is the next-highest version that is not hidden.
# However, if we downgrade D, we will also downgrade C to C1.
# And C1 requires B2.hidden, and B2.hidden also meets our requirements:
# it is compatible with D1 and a strict downgrade from B3.
#
# Since neither the initial nor the final build list includes B1,
# and the nothing in the final downgraded build list requires E at all,
# no dependency on E1 (required by only B1) should be introduced.
#
name: downhiddenartifact
A: B3 C2
A1: B3
B1: E1
B2.hidden:
B3: D2
C1: B2.hidden
C2: D2
D1:
D2:
build A1: A1 B3 D2
downgrade A1 D1: A1 B1 D1 E1
build A: A B3 C2 D2
downgrade A D1: A B2.hidden C1 D1

# Both B3 and C3 require D2.
# If we downgrade D to D1, then in isolation B3 would downgrade to B1,
# and C3 would downgrade to C1.
# But C1 requires B2.hidden, and B1 requires C2.hidden, so we can't
# downgrade to either of those without pulling the other back up a little.
#
# B2.hidden and C2.hidden are both compatible with D1, so that still
# meets our requirements — but then we're in an odd state in which
# B and C have both been downgraded to hidden versions, without any
# remaining requirements to explain how those hidden versions got there.
#
# TODO(bcmills): Would it be better to force downgrades to land on non-hidden
# versions?
# In this case, that would remove the dependencies on B and C entirely.
#
name: downhiddencross
A: B3 C3
B1: C2.hidden
B2.hidden:
B3: D2
C1: B2.hidden
C2.hidden:
C3: D2
D1:
D2:
build A: A B3 C3 D2
downgrade A D1: A B2.hidden C2.hidden D1

# golang.org/issue/25542.
name: noprev1
A: B4 C2
B2.hidden:
C2:
build A:               A B4        C2
downgrade A B2.hidden: A B2.hidden C2

name: noprev2
A: B4 C2
B2.hidden:
B1:
C2:
build A:               A B4        C2
downgrade A B2.hidden: A B2.hidden C2

name: noprev3
A: B4 C2
B3:
B2.hidden:
C2:
build A:               A B4        C2
downgrade A B2.hidden: A B2.hidden C2

# Cycles involving the target.

# The target must be the newest version of itself.
name: cycle1
A: B1
B1: A1
B2: A2
B3: A3
build A:      A B1
upgrade A B2: A B2
upgrade* A:   A B3

# golang.org/issue/29773:
# Requirements of older versions of the target
# must be carried over.
name: cycle2
A: B1
A1: C1
A2: D1
B1: A1
B2: A2
C1: A2
C2:
D2:
build A:    A B1 C1 D1
upgrade* A: A B2 C2 D2

# Cycles with multiple possible solutions.
# (golang.org/issue/34086)
name: cycle3
M: A1 C2
A1: B1
B1: C1
B2: C2
C1:
C2: B2
build M: M A1 B2 C2
req M:     A1 B2
req M A:   A1 B2
req M C:   A1 C2

# Requirement minimization.

name: req1
A: B1 C1 D1 E1 F1
B1: C1 E1 F1
req A:   B1    D1
req A C: B1 C1 D1

name: req2
A: G1 H1
G1: H1
H1: G1
req A:   G1
req A G: G1
req A H: H1

name: req3
M: A1 B1
A1: X1
B1: X2
X1: I1
X2:
req M: A1 B1

name: reqnone
M: Anone B1 D1 E1
B1: Cnone D1
E1: Fnone
build M: M B1 D1 E1
req M:     B1    E1

name: reqdup
M: A1 B1
A1: B1
B1:
req M A A: A1

name: reqcross
M: A1 B1 C1
A1: B1 C1
B1: C1
C1:
req M A B: A1 B1
`

func Test(t *testing.T) {
	var (
		name string
		reqs reqsMap
		fns  []func(*testing.T)
	)
	flush := func() {
		if name != "" {
			t.Run(name, func(t *testing.T) {
				for _, fn := range fns {
					fn(t)
				}
				if len(fns) == 0 {
					t.Errorf("no functions tested")
				}
			})
		}
	}
	m := func(s string) module.Version {
		return module.Version{Path: s[:1], Version: s[1:]}
	}
	ms := func(list []string) []module.Version {
		var mlist []module.Version
		for _, s := range list {
			mlist = append(mlist, m(s))
		}
		return mlist
	}
	checkList := func(t *testing.T, desc string, list []module.Version, err error, val string) {
		if err != nil {
			t.Fatalf("%s: %v", desc, err)
		}
		vs := ms(strings.Fields(val))
		if !reflect.DeepEqual(list, vs) {
			t.Errorf("%s = %v, want %v", desc, list, vs)
		}
	}

	for _, line := range strings.Split(tests, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		i := strings.Index(line, ":")
		if i < 0 {
			t.Fatalf("missing colon: %q", line)
		}
		key := strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		if key == "" {
			t.Fatalf("missing key: %q", line)
		}
		kf := strings.Fields(key)
		switch kf[0] {
		case "name":
			if len(kf) != 1 {
				t.Fatalf("name takes no arguments: %q", line)
			}
			flush()
			reqs = make(reqsMap)
			fns = nil
			name = val
			continue
		case "build":
			if len(kf) != 2 {
				t.Fatalf("build takes one argument: %q", line)
			}
			fns = append(fns, func(t *testing.T) {
				list, err := BuildList([]module.Version{m(kf[1])}, reqs)
				checkList(t, key, list, err, val)
			})
			continue
		case "upgrade*":
			if len(kf) != 2 {
				t.Fatalf("upgrade* takes one argument: %q", line)
			}
			fns = append(fns, func(t *testing.T) {
				list, err := UpgradeAll(m(kf[1]), reqs)
				checkList(t, key, list, err, val)
			})
			continue
		case "upgradereq":
			if len(kf) < 2 {
				t.Fatalf("upgrade takes at least one argument: %q", line)
			}
			fns = append(fns, func(t *testing.T) {
				list, err := Upgrade(m(kf[1]), reqs, ms(kf[2:])...)
				if err == nil {
					// Copy the reqs map, but substitute the upgraded requirements in
					// place of the target's original requirements.
					upReqs := make(reqsMap, len(reqs))
					for m, r := range reqs {
						upReqs[m] = r
					}
					upReqs[m(kf[1])] = list

					list, err = Req(m(kf[1]), nil, upReqs)
				}
				checkList(t, key, list, err, val)
			})
			continue
		case "upgrade":
			if len(kf) < 2 {
				t.Fatalf("upgrade takes at least one argument: %q", line)
			}
			fns = append(fns, func(t *testing.T) {
				list, err := Upgrade(m(kf[1]), reqs, ms(kf[2:])...)
				checkList(t, key, list, err, val)
			})
			continue
		case "downgrade":
			if len(kf) < 2 {
				t.Fatalf("downgrade takes at least one argument: %q", line)
			}
			fns = append(fns, func(t *testing.T) {
				list, err := Downgrade(m(kf[1]), reqs, ms(kf[1:])...)
				checkList(t, key, list, err, val)
			})
			continue
		case "req":
			if len(kf) < 2 {
				t.Fatalf("req takes at least one argument: %q", line)
			}
			fns = append(fns, func(t *testing.T) {
				list, err := Req(m(kf[1]), kf[2:], reqs)
				checkList(t, key, list, err, val)
			})
			continue
		}
		if len(kf) == 1 && 'A' <= key[0] && key[0] <= 'Z' {
			var rs []module.Version
			for _, f := range strings.Fields(val) {
				r := m(f)
				if reqs[r] == nil {
					reqs[r] = []module.Version{}
				}
				rs = append(rs, r)
			}
			reqs[m(key)] = rs
			continue
		}
		t.Fatalf("bad line: %q", line)
	}
	flush()
}

type reqsMap map[module.Version][]module.Version

func (r reqsMap) Max(_, v1, v2 string) string {
	if v1 == "none" || v2 == "" {
		return v2
	}
	if v2 == "none" || v1 == "" {
		return v1
	}
	if v1 < v2 {
		return v2
	}
	return v1
}

func (r reqsMap) Upgrade(m module.Version) (module.Version, error) {
	u := module.Version{Version: "none"}
	for k := range r {
		if k.Path == m.Path && r.Max(k.Path, u.Version, k.Version) == k.Version && !strings.HasSuffix(k.Version, ".hidden") {
			u = k
		}
	}
	if u.Path == "" {
		return module.Version{}, fmt.Errorf("missing module: %v", module.Version{Path: m.Path})
	}
	return u, nil
}

func (r reqsMap) Previous(m module.Version) (module.Version, error) {
	var p module.Version
	for k := range r {
		if k.Path == m.Path && p.Version < k.Version && k.Version < m.Version && !strings.HasSuffix(k.Version, ".hidden") {
			p = k
		}
	}
	if p.Path == "" {
		return module.Version{Path: m.Path, Version: "none"}, nil
	}
	return p, nil
}

func (r reqsMap) Required(m module.Version) ([]module.Version, error) {
	rr, ok := r[m]
	if !ok {
		return nil, fmt.Errorf("missing module: %v", m)
	}
	return rr, nil
}
```