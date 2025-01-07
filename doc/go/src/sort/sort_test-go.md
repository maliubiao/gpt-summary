Response:
Let's break down the thought process for analyzing the provided Go code and answering the request.

**1. Understanding the Request:**

The request asks for a breakdown of the `sort_test.go` file's functionality, focusing on:

* **Primary Function:** What does this file do?
* **Go Feature Illustration:** Can we identify specific Go sorting features being tested and provide examples?
* **Code Reasoning:**  If examples involve reasoning about inputs and outputs, provide those.
* **Command-line Arguments:** Are there any command-line arguments handled? (Likely not in a test file, but worth considering.)
* **Common Mistakes:**  Any pitfalls users might encounter?
* **Answer in Chinese.**

**2. Initial Scan and Identification of Key Components:**

A quick scan reveals several test functions (names starting with `Test`), benchmark functions (names starting with `Benchmark`), and some global variable declarations. This immediately suggests the file's primary purpose: **testing the `sort` package**.

**3. Analyzing Test Functions (The Core Functionality):**

The majority of the code consists of test functions. Each test function aims to verify specific aspects of the `sort` package. I'll go through them one by one:

* `TestSortIntSlice`, `TestSortFloat64Slice`, `TestSortStringSlice`: These test the `Sort` function with specific `IntSlice`, `Float64Slice`, and `StringSlice` types. This reveals the existence of these type-specific slice adapters for sorting.
* `TestSortFloat64sCompareSlicesSort`: This explicitly compares the `sort.Sort` behavior with `slices.Sort` for float64s, specifically handling NaNs. This points to a potential difference or nuance in NaN handling between the two.
* `TestInts`, `TestFloat64s`, `TestStrings`: These test the convenience functions `Ints`, `Float64s`, and `Strings`, which directly operate on `[]int`, `[]float64`, and `[]string`.
* `TestSlice`: This tests the generic `Slice` function, taking a slice and a custom comparison function. This highlights the flexibility of the `sort` package.
* `TestSortLarge_Random`: This tests sorting a large slice of random integers, likely focusing on performance or correctness with scale.
* `TestReverseSortIntSlice`: This tests the `Reverse` function used in conjunction with `Sort`.
* `TestBreakPatterns`:  This test case is interesting. The comment suggests it's designed to trigger a specific optimization or handling of certain data patterns within the sorting algorithm.
* `TestReverseRange`: This tests the `ReverseRange` function, which reverses a portion of a slice.
* `TestNonDeterministicComparison`:  This is a crucial test for robustness. It checks if `sort.Sort` can handle inconsistent comparison functions without panicking. This demonstrates a safeguard in the implementation.
* `TestAdversary`: This test is designed to deliberately provide input that might cause quicksort to perform poorly, ensuring the algorithm falls back to a more robust sort like heapsort.
* `TestStableInts`, `TestStability`: These test the `Stable` sorting function, focusing on maintaining the relative order of equal elements.

**4. Analyzing Benchmark Functions (Performance Evaluation):**

The benchmark functions (starting with `Benchmark`) are for performance testing. They measure the execution time of different sorting functions with varying data types and sizes. These confirm the existence of `Stable`, `Slice`, `Ints`, and `Strings` functions within the `sort` package. The variations (e.g., `_Sorted`, `_Reversed`, `_Mod8`) test performance on different data distributions.

**5. Identifying Supporting Structures and Functions:**

* `ints`, `float64s`, `stringsData`: These global variables provide sample data for the tests.
* `nonDeterministicTestingData`:  A custom type used for the non-deterministic comparison test.
* `testingData`, `adversaryTestingData`, `intPairs`:  Custom types used in more complex testing scenarios, especially for benchmarking and testing stability and adversarial inputs.
* `lg`: A helper function to calculate the logarithm base 2, likely used for estimating complexity in the Bentley-McIlroy tests.
* `testBentleyMcIlroy`: A sophisticated test function that runs the sorting algorithms against various data distributions and initial orderings, based on the well-known Bentley-McIlroy test suite.
* `countOps`: A function to count the number of comparisons and swaps performed by a sorting algorithm.

**6. Connecting the Dots and Inferring Go Features:**

By examining the test cases, I can infer the following Go `sort` package features:

* **Generic `Sort` Function:** Takes a `sort.Interface`.
* **`sort.Interface`:** Requires `Len()`, `Less(i, j int) bool`, and `Swap(i, j int)`.
* **Type-Specific Slice Adapters:** `IntSlice`, `Float64Slice`, `StringSlice` provide `sort.Interface` implementations for basic types.
* **Convenience Functions:** `Ints`, `Float64s`, `Strings` for directly sorting slices of basic types.
* **Generic `Slice` Function:** Sorts using a custom less function.
* **`Reverse` Function:** Returns a reversed view of a `sort.Interface`.
* **`ReverseRange` Function:** Reverses a portion of a slice.
* **`Stable` Function:** Performs a stable sort.
* **`Heapsort` Function:**  An alternative sorting algorithm exposed for testing or specific use cases.
* **`IsSorted` and `SliceIsSorted` Functions:**  Check if a slice is sorted.

**7. Constructing the Answer:**

Now, I can organize the findings into a comprehensive answer, addressing each point of the request:

* **功能列举:** List the discovered functionalities.
* **Go 代码示例:**  Choose relevant test cases and adapt them into illustrative examples, providing sample input and expected output.
* **代码推理:** For the more complex tests (like `TestBreakPatterns` or `TestAdversary`), explain the likely intention and provide hypothetical scenarios.
* **命令行参数:** Explicitly state that no command-line arguments are processed in this *test* file.
* **易犯错的点:** Based on the test cases, identify potential pitfalls for users (e.g., assuming stability with `Sort`, incorrect comparison functions with `Slice`).
* **使用中文回答:**  Translate the entire response into Chinese.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Perhaps the file handles command-line arguments for running specific tests. **Correction:**  Reviewing the code confirms it's a standard Go test file using the `testing` package, which uses `go test` and doesn't involve custom argument parsing within the file itself.
* **Initial thought:** Focus only on the basic sorting functions. **Correction:**  The file includes tests for stability, reversing, and even adversarial scenarios, which are important aspects of the `sort` package. Ensure these are covered.
* **Consideration:** Should I explain the internal workings of the sorting algorithms? **Decision:** The request focuses on the *functionality* being tested, not the internal implementation. Keep the explanations at a higher level.

By following this systematic analysis and refinement, I can generate a detailed and accurate response to the request.
这段代码是 Go 语言标准库 `sort` 包的测试代码，位于 `go/src/sort/sort_test.go`。它的主要功能是**测试 `sort` 包中提供的各种排序算法和相关工具函数的正确性和性能**。

具体来说，它测试了以下功能：

1. **基本排序功能：**
   - **对不同类型的切片进行排序：**  测试了 `Sort` 函数与 `IntSlice`、`Float64Slice`、`StringSlice` 结合使用，分别对 `int`、`float64` 和 `string` 类型的切片进行排序。
   - **使用便捷函数排序：** 测试了直接对 `[]int`、`[]float64` 和 `[]string` 使用 `Ints`、`Float64s` 和 `Strings` 函数进行排序。
   - **使用自定义比较函数排序：** 测试了 `Slice` 函数，允许用户提供自定义的比较函数来对任意类型的切片进行排序。

2. **排序的正确性验证：**
   - **`IsSorted` 系列函数：** 使用 `IsSorted`、`IntsAreSorted`、`Float64sAreSorted` 和 `StringsAreSorted` 来验证排序后的切片是否确实已排序。

3. **特定场景的测试：**
   - **包含 NaN 的浮点数排序：**  `TestSortFloat64sCompareSlicesSort` 测试了 `sort.Sort` 如何处理包含 `NaN` (Not a Number) 的 `float64` 切片，并与 `slices.Sort` 的行为进行比较，强调了 `cmp.Compare` 在 NaN 比较中的作用。
   - **大规模随机数据排序：** `TestSortLarge_Random` 测试了排序算法在处理大量随机数据时的性能和正确性。
   - **反向排序：** `TestReverseSortIntSlice` 测试了使用 `Reverse` 函数来对切片进行反向排序。
   - **特定模式的数据排序：** `TestBreakPatterns` 旨在测试排序算法在处理具有特定重复模式的数据时的鲁棒性，可能触发算法内部的一些优化路径。
   - **反转切片指定范围：** `TestReverseRange` 测试了 `ReverseRange` 函数，用于反转切片中指定范围的元素。
   - **非确定性比较：** `TestNonDeterministicComparison`  测试了当提供的比较函数返回不一致的结果时，`Sort` 函数是否会panic，确保了算法的健壮性。
   - **对抗性测试：** `TestAdversary`  使用了被称为 "antiquicksort" 的方法，生成特定的输入数据来尽可能使快速排序算法退化到 O(n^2) 的性能，从而测试 Go 排序算法的兜底策略（通常会回退到堆排序）。

4. **稳定性测试：**
   - **`Stable` 系列函数：**  测试了 `Stable` 函数和 `SliceStable` 函数，验证了稳定排序算法在排序后是否保持了相等元素的相对顺序。

5. **性能基准测试：**
   - **`Benchmark` 系列函数：**  包含了大量的基准测试，用于评估不同排序算法在不同数据类型、数据规模和初始状态下的性能，例如 `BenchmarkSortString1K`、`BenchmarkStableInt1K` 等。这些测试会测量排序操作的耗时。

**推理出的 Go 语言功能实现 (以及代码示例):**

这个测试文件主要测试了 `sort` 包提供的通用排序接口 `sort.Interface` 以及基于该接口实现的具体排序算法和便捷函数。

**1. `sort.Interface` 接口：**

`sort.Interface` 是 `sort` 包的核心，它定义了任何可以被排序的数据结构必须实现的三个方法：

```go
type Interface interface {
	Len() int
	Less(i, j int) bool // i, j are indices of the element to compare.
	Swap(i, j int)      // Swaps the elements with indices i and j.
}
```

测试代码中，`IntSlice`、`Float64Slice` 和 `StringSlice` 类型都实现了 `sort.Interface`。

**代码示例：**

```go
package main

import (
	"fmt"
	"sort"
)

type MyIntSlice []int

func (m MyIntSlice) Len() int           { return len(m) }
func (m MyIntSlice) Less(i, j int) bool { return m[i] < m[j] }
func (m MyIntSlice) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }

func main() {
	data := MyIntSlice{5, 2, 8, 1, 9}
	sort.Sort(data) // 使用 sort.Sort 函数，它接受任何实现了 sort.Interface 的类型
	fmt.Println(data) // Output: [1 2 5 8 9]
}
```

**假设的输入与输出：**

在上面的例子中，输入是 `MyIntSlice{5, 2, 8, 1, 9}`，输出是 `[1 2 5 8 9]`。

**2. 通用排序函数 `sort.Sort`：**

`sort.Sort` 函数接受任何实现了 `sort.Interface` 的类型，并对其进行排序。

**代码示例：**  见上面的 `MyIntSlice` 示例。

**3. 类型特定的切片类型 (`IntSlice`, `Float64Slice`, `StringSlice`)：**

`sort` 包提供了预定义的切片类型，方便对基本类型进行排序。

**代码示例（在测试代码中已经有体现）：**

```go
func TestSortIntSliceExample(t *testing.T) {
	data := []int{74, 59, 238, -784}
	a := sort.IntSlice(data) // 将 []int 转换为 sort.IntSlice
	sort.Sort(a)             // 使用 sort.Sort 排序
	fmt.Println(data)        // Output: [-784 59 74 238]
}
```

**假设的输入与输出：**

输入 `data` 为 `[]int{74, 59, 238, -784}`，输出为 `[-784 59 74 238]`。

**4. 便捷排序函数 (`Ints`, `Float64s`, `Strings`)：**

这些函数可以直接对对应类型的切片进行排序，无需显式转换为 `sort.Interface`。

**代码示例（在测试代码中已经有体现）：**

```go
func TestIntsExample(t *testing.T) {
	data := []int{74, 59, 238, -784}
	sort.Ints(data) // 直接使用 sort.Ints 排序
	fmt.Println(data) // Output: [-784 59 74 238]
}
```

**假设的输入与输出：**

输入 `data` 为 `[]int{74, 59, 238, -784}`，输出为 `[-784 59 74 238]`。

**5. 使用自定义比较函数的排序 (`sort.Slice`)：**

`sort.Slice` 函数允许你提供一个匿名函数或具名函数作为比较器。

**代码示例（基于测试代码中的 `TestSlice`）：**

```go
func TestSliceExample(t *testing.T) {
	data := []string{"banana", "apple", "cherry"}
	sort.Slice(data, func(i, j int) bool {
		return len(data[i]) < len(data[j]) // 按字符串长度排序
	})
	fmt.Println(data) // Output: [apple banana cherry]
}
```

**假设的输入与输出：**

输入 `data` 为 `[]string{"banana", "apple", "cherry"}`，输出为 `[apple banana cherry]`。

**6. 稳定排序 (`sort.Stable`)：**

`sort.Stable` 函数执行稳定排序，保证相等元素的相对顺序不变。

**代码示例（基于测试代码中的 `TestStability`）：**

```go
package main

import (
	"fmt"
	"sort"
)

type Pair struct {
	Value int
	Order int
}

type Pairs []Pair

func (p Pairs) Len() int           { return len(p) }
func (p Pairs) Less(i, j int) bool { return p[i].Value < p[j].Value }
func (p Pairs) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

func main() {
	data := Pairs{
		{Value: 3, Order: 1},
		{Value: 1, Order: 2},
		{Value: 3, Order: 3},
		{Value: 2, Order: 4},
	}

	sort.Stable(data)
	for _, pair := range data {
		fmt.Printf("{Value: %d, Order: %d} ", pair)
	}
	// Output: {Value: 1, Order: 2} {Value: 2, Order: 4} {Value: 3, Order: 1} {Value: 3, Order: 3}
}
```

**假设的输入与输出：**

输入 `data` 为 `Pairs{ {Value: 3, Order: 1}, {Value: 1, Order: 2}, {Value: 3, Order: 3}, {Value: 2, Order: 4} }`，输出保持了相同 `Value` 的元素的原始 `Order`：`{Value: 1, Order: 2} {Value: 2, Order: 4} {Value: 3, Order: 1} {Value: 3, Order: 3}`。

**7. 反向排序 (`sort.Reverse`)：**

`sort.Reverse` 函数返回一个包装了 `sort.Interface` 的结构，使得排序顺序反转。

**代码示例（基于测试代码中的 `TestReverseSortIntSlice`）：**

```go
package main

import (
	"fmt"
	"sort"
)

func main() {
	data := []int{1, 5, 2, 8, 3}
	sort.Sort(sort.Reverse(sort.IntSlice(data)))
	fmt.Println(data) // Output: [8 5 3 2 1]
}
```

**假设的输入与输出：**

输入 `data` 为 `[]int{1, 5, 2, 8, 3}`，输出为反向排序后的结果 `[8 5 3 2 1]`。

**命令行参数的具体处理：**

这个测试文件本身不处理任何命令行参数。Go 语言的测试是通过 `go test` 命令来执行的，可以通过一些 `go test` 的标志来控制测试行为，例如：

- `-v`:  显示更详细的测试输出。
- `-run <正则表达式>`:  只运行匹配正则表达式的测试函数。
- `-bench <正则表达式>`:  只运行匹配正则表达式的基准测试函数。
- `-count n`:  运行每个测试或基准测试 n 次。
- `-cpuprofile <文件>`:  将 CPU 分析数据写入指定文件。
- `-memprofile <文件>`:  将内存分析数据写入指定文件。

例如，要只运行 `TestSortIntSlice` 这个测试，可以使用命令：

```bash
go test -v -run TestSortIntSlice
```

要运行所有的基准测试，可以使用命令：

```bash
go test -bench=.
```

**使用者易犯错的点：**

1. **误认为 `sort.Sort` 是稳定的：**  `sort.Sort` 使用的是不稳定的排序算法（通常是快速排序），因此对于相等元素的相对顺序不保证保持不变。如果需要稳定排序，必须使用 `sort.Stable`。

   **错误示例：**

   ```go
   package main

   import (
	   "fmt"
	   "sort"
   )

   type Pair struct {
	   Value int
	   Order int
   }

   type Pairs []Pair

   func (p Pairs) Len() int           { return len(p) }
   func (p Pairs) Less(i, j int) bool { return p[i].Value < p[j].Value }
   func (p Pairs) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }

   func main() {
	   data := Pairs{
		   {Value: 3, Order: 1},
		   {Value: 1, Order: 2},
		   {Value: 3, Order: 3},
		   {Value: 2, Order: 4},
	   }

	   sort.Sort(data) // 使用不稳定的 sort.Sort
	   for _, pair := range data {
		   fmt.Printf("{Value: %d, Order: %d} ", pair)
	   }
	   // 可能的输出: {Value: 1, Order: 2} {Value: 2, Order: 4} {Value: 3, Order: 3} {Value: 3, Order: 1} (Order 可能会变)
   }
   ```

2. **在使用 `sort.Slice` 时提供错误的比较函数：** 比较函数必须满足严格弱排序的性质，即对于元素 `a` 和 `b`：
   - 如果 `Less(a, b)` 为 `true`，则 `Less(b, a)` 必须为 `false`。
   - 如果 `Less(a, b)` 和 `Less(b, c)` 都为 `true`，则 `Less(a, c)` 必须为 `true` (传递性)。

   **错误示例：**

   ```go
   package main

   import (
	   "fmt"
	   "sort"
   )

   func main() {
	   data := []int{3, 1, 4, 1, 5, 9, 2, 6}
	   sort.Slice(data, func(i, j int) bool {
		   return data[i] <= data[j] // 错误：使用了 <=，不满足严格弱排序
	   })
	   fmt.Println(data) // 可能导致排序结果不正确或 panic
   }
   ```

总而言之，`go/src/sort/sort_test.go` 是一个全面的测试套件，用于确保 Go 语言 `sort` 包的各种功能按照预期工作，并且性能良好。通过阅读和分析这些测试代码，可以深入了解 `sort` 包的使用方法和内部实现的一些细节。

Prompt: 
```
这是路径为go/src/sort/sort_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sort_test

import (
	"cmp"
	"fmt"
	"internal/testenv"
	"math"
	"math/rand/v2"
	"slices"
	. "sort"
	"strconv"
	"strings"
	"testing"
)

var ints = [...]int{74, 59, 238, -784, 9845, 959, 905, 0, 0, 42, 7586, -5467984, 7586}
var float64s = [...]float64{74.3, 59.0, math.Inf(1), 238.2, -784.0, 2.3, math.NaN(), math.NaN(), math.Inf(-1), 9845.768, -959.7485, 905, 7.8, 7.8}
var stringsData = [...]string{"", "Hello", "foo", "bar", "foo", "f00", "%*&^*&^&", "***"}

func TestSortIntSlice(t *testing.T) {
	data := ints
	a := IntSlice(data[0:])
	Sort(a)
	if !IsSorted(a) {
		t.Errorf("sorted %v", ints)
		t.Errorf("   got %v", data)
	}
}

func TestSortFloat64Slice(t *testing.T) {
	data := float64s
	a := Float64Slice(data[0:])
	Sort(a)
	if !IsSorted(a) {
		t.Errorf("sorted %v", float64s)
		t.Errorf("   got %v", data)
	}
}

// Compare Sort with slices.Sort sorting a float64 slice containing NaNs.
func TestSortFloat64sCompareSlicesSort(t *testing.T) {
	slice1 := slices.Clone(float64s[:])
	slice2 := slices.Clone(float64s[:])

	Sort(Float64Slice(slice1))
	slices.Sort(slice2)

	// Compare for equality using cmp.Compare, which considers NaNs equal.
	if !slices.EqualFunc(slice1, slice2, func(a, b float64) bool { return cmp.Compare(a, b) == 0 }) {
		t.Errorf("mismatch between Sort and slices.Sort: got %v, want %v", slice1, slice2)
	}
}

func TestSortStringSlice(t *testing.T) {
	data := stringsData
	a := StringSlice(data[0:])
	Sort(a)
	if !IsSorted(a) {
		t.Errorf("sorted %v", stringsData)
		t.Errorf("   got %v", data)
	}
}

func TestInts(t *testing.T) {
	data := ints
	Ints(data[0:])
	if !IntsAreSorted(data[0:]) {
		t.Errorf("sorted %v", ints)
		t.Errorf("   got %v", data)
	}
}

func TestFloat64s(t *testing.T) {
	data := float64s
	Float64s(data[0:])
	if !Float64sAreSorted(data[0:]) {
		t.Errorf("sorted %v", float64s)
		t.Errorf("   got %v", data)
	}
}

func TestStrings(t *testing.T) {
	data := stringsData
	Strings(data[0:])
	if !StringsAreSorted(data[0:]) {
		t.Errorf("sorted %v", stringsData)
		t.Errorf("   got %v", data)
	}
}

func TestSlice(t *testing.T) {
	data := stringsData
	Slice(data[:], func(i, j int) bool {
		return data[i] < data[j]
	})
	if !SliceIsSorted(data[:], func(i, j int) bool { return data[i] < data[j] }) {
		t.Errorf("sorted %v", stringsData)
		t.Errorf("   got %v", data)
	}
}

func TestSortLarge_Random(t *testing.T) {
	n := 1000000
	if testing.Short() {
		n /= 100
	}
	data := make([]int, n)
	for i := 0; i < len(data); i++ {
		data[i] = rand.IntN(100)
	}
	if IntsAreSorted(data) {
		t.Fatalf("terrible rand.rand")
	}
	Ints(data)
	if !IntsAreSorted(data) {
		t.Errorf("sort didn't sort - 1M ints")
	}
}

func TestReverseSortIntSlice(t *testing.T) {
	data := ints
	data1 := ints
	a := IntSlice(data[0:])
	Sort(a)
	r := IntSlice(data1[0:])
	Sort(Reverse(r))
	for i := 0; i < len(data); i++ {
		if a[i] != r[len(data)-1-i] {
			t.Errorf("reverse sort didn't sort")
		}
		if i > len(data)/2 {
			break
		}
	}
}

func TestBreakPatterns(t *testing.T) {
	// Special slice used to trigger breakPatterns.
	data := make([]int, 30)
	for i := range data {
		data[i] = 10
	}
	data[(len(data)/4)*1] = 0
	data[(len(data)/4)*2] = 1
	data[(len(data)/4)*3] = 2
	Sort(IntSlice(data))
}

func TestReverseRange(t *testing.T) {
	data := []int{1, 2, 3, 4, 5, 6, 7}
	ReverseRange(IntSlice(data), 0, len(data))
	for i := len(data) - 1; i > 0; i-- {
		if data[i] > data[i-1] {
			t.Fatalf("reverseRange didn't work")
		}
	}

	data1 := []int{1, 2, 3, 4, 5, 6, 7}
	data2 := []int{1, 2, 5, 4, 3, 6, 7}
	ReverseRange(IntSlice(data1), 2, 5)
	for i, v := range data1 {
		if v != data2[i] {
			t.Fatalf("reverseRange didn't work")
		}
	}
}

type nonDeterministicTestingData struct {
	r *rand.Rand
}

func (t *nonDeterministicTestingData) Len() int {
	return 500
}
func (t *nonDeterministicTestingData) Less(i, j int) bool {
	if i < 0 || j < 0 || i >= t.Len() || j >= t.Len() {
		panic("nondeterministic comparison out of bounds")
	}
	return t.r.Float32() < 0.5
}
func (t *nonDeterministicTestingData) Swap(i, j int) {
	if i < 0 || j < 0 || i >= t.Len() || j >= t.Len() {
		panic("nondeterministic comparison out of bounds")
	}
}

func TestNonDeterministicComparison(t *testing.T) {
	// Ensure that sort.Sort does not panic when Less returns inconsistent results.
	// See https://golang.org/issue/14377.
	defer func() {
		if r := recover(); r != nil {
			t.Error(r)
		}
	}()

	td := &nonDeterministicTestingData{
		r: rand.New(rand.NewPCG(0, 0)),
	}

	for i := 0; i < 10; i++ {
		Sort(td)
	}
}

func BenchmarkSortString1K(b *testing.B) {
	b.StopTimer()
	unsorted := make([]string, 1<<10)
	for i := range unsorted {
		unsorted[i] = strconv.Itoa(i ^ 0x2cc)
	}
	data := make([]string, len(unsorted))

	for i := 0; i < b.N; i++ {
		copy(data, unsorted)
		b.StartTimer()
		Strings(data)
		b.StopTimer()
	}
}

func BenchmarkSortString1K_Slice(b *testing.B) {
	b.StopTimer()
	unsorted := make([]string, 1<<10)
	for i := range unsorted {
		unsorted[i] = strconv.Itoa(i ^ 0x2cc)
	}
	data := make([]string, len(unsorted))

	for i := 0; i < b.N; i++ {
		copy(data, unsorted)
		b.StartTimer()
		Slice(data, func(i, j int) bool { return data[i] < data[j] })
		b.StopTimer()
	}
}

func BenchmarkStableString1K(b *testing.B) {
	b.StopTimer()
	unsorted := make([]string, 1<<10)
	for i := range unsorted {
		unsorted[i] = strconv.Itoa(i ^ 0x2cc)
	}
	data := make([]string, len(unsorted))

	for i := 0; i < b.N; i++ {
		copy(data, unsorted)
		b.StartTimer()
		Stable(StringSlice(data))
		b.StopTimer()
	}
}

func BenchmarkSortInt1K(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		data := make([]int, 1<<10)
		for i := 0; i < len(data); i++ {
			data[i] = i ^ 0x2cc
		}
		b.StartTimer()
		Ints(data)
		b.StopTimer()
	}
}

func BenchmarkSortInt1K_Sorted(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		data := make([]int, 1<<10)
		for i := 0; i < len(data); i++ {
			data[i] = i
		}
		b.StartTimer()
		Ints(data)
		b.StopTimer()
	}
}

func BenchmarkSortInt1K_Reversed(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		data := make([]int, 1<<10)
		for i := 0; i < len(data); i++ {
			data[i] = len(data) - i
		}
		b.StartTimer()
		Ints(data)
		b.StopTimer()
	}
}

func BenchmarkSortInt1K_Mod8(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		data := make([]int, 1<<10)
		for i := 0; i < len(data); i++ {
			data[i] = i % 8
		}
		b.StartTimer()
		Ints(data)
		b.StopTimer()
	}
}

func BenchmarkStableInt1K(b *testing.B) {
	b.StopTimer()
	unsorted := make([]int, 1<<10)
	for i := range unsorted {
		unsorted[i] = i ^ 0x2cc
	}
	data := make([]int, len(unsorted))
	for i := 0; i < b.N; i++ {
		copy(data, unsorted)
		b.StartTimer()
		Stable(IntSlice(data))
		b.StopTimer()
	}
}

func BenchmarkStableInt1K_Slice(b *testing.B) {
	b.StopTimer()
	unsorted := make([]int, 1<<10)
	for i := range unsorted {
		unsorted[i] = i ^ 0x2cc
	}
	data := make([]int, len(unsorted))
	for i := 0; i < b.N; i++ {
		copy(data, unsorted)
		b.StartTimer()
		SliceStable(data, func(i, j int) bool { return data[i] < data[j] })
		b.StopTimer()
	}
}

func BenchmarkSortInt64K(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		data := make([]int, 1<<16)
		for i := 0; i < len(data); i++ {
			data[i] = i ^ 0xcccc
		}
		b.StartTimer()
		Ints(data)
		b.StopTimer()
	}
}

func BenchmarkSortInt64K_Slice(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		data := make([]int, 1<<16)
		for i := 0; i < len(data); i++ {
			data[i] = i ^ 0xcccc
		}
		b.StartTimer()
		Slice(data, func(i, j int) bool { return data[i] < data[j] })
		b.StopTimer()
	}
}

func BenchmarkStableInt64K(b *testing.B) {
	b.StopTimer()
	for i := 0; i < b.N; i++ {
		data := make([]int, 1<<16)
		for i := 0; i < len(data); i++ {
			data[i] = i ^ 0xcccc
		}
		b.StartTimer()
		Stable(IntSlice(data))
		b.StopTimer()
	}
}

const (
	_Sawtooth = iota
	_Rand
	_Stagger
	_Plateau
	_Shuffle
	_NDist
)

const (
	_Copy = iota
	_Reverse
	_ReverseFirstHalf
	_ReverseSecondHalf
	_Sorted
	_Dither
	_NMode
)

type testingData struct {
	desc        string
	t           *testing.T
	data        []int
	maxswap     int // number of swaps allowed
	ncmp, nswap int
}

func (d *testingData) Len() int { return len(d.data) }
func (d *testingData) Less(i, j int) bool {
	d.ncmp++
	return d.data[i] < d.data[j]
}
func (d *testingData) Swap(i, j int) {
	if d.nswap >= d.maxswap {
		d.t.Fatalf("%s: used %d swaps sorting slice of %d", d.desc, d.nswap, len(d.data))
	}
	d.nswap++
	d.data[i], d.data[j] = d.data[j], d.data[i]
}

func lg(n int) int {
	i := 0
	for 1<<uint(i) < n {
		i++
	}
	return i
}

func testBentleyMcIlroy(t *testing.T, sort func(Interface), maxswap func(int) int) {
	sizes := []int{100, 1023, 1024, 1025}
	if testing.Short() {
		sizes = []int{100, 127, 128, 129}
	}
	dists := []string{"sawtooth", "rand", "stagger", "plateau", "shuffle"}
	modes := []string{"copy", "reverse", "reverse1", "reverse2", "sort", "dither"}
	var tmp1, tmp2 [1025]int
	for _, n := range sizes {
		for m := 1; m < 2*n; m *= 2 {
			for dist := 0; dist < _NDist; dist++ {
				j := 0
				k := 1
				data := tmp1[0:n]
				for i := 0; i < n; i++ {
					switch dist {
					case _Sawtooth:
						data[i] = i % m
					case _Rand:
						data[i] = rand.IntN(m)
					case _Stagger:
						data[i] = (i*m + i) % n
					case _Plateau:
						data[i] = min(i, m)
					case _Shuffle:
						if rand.IntN(m) != 0 {
							j += 2
							data[i] = j
						} else {
							k += 2
							data[i] = k
						}
					}
				}

				mdata := tmp2[0:n]
				for mode := 0; mode < _NMode; mode++ {
					switch mode {
					case _Copy:
						for i := 0; i < n; i++ {
							mdata[i] = data[i]
						}
					case _Reverse:
						for i := 0; i < n; i++ {
							mdata[i] = data[n-i-1]
						}
					case _ReverseFirstHalf:
						for i := 0; i < n/2; i++ {
							mdata[i] = data[n/2-i-1]
						}
						for i := n / 2; i < n; i++ {
							mdata[i] = data[i]
						}
					case _ReverseSecondHalf:
						for i := 0; i < n/2; i++ {
							mdata[i] = data[i]
						}
						for i := n / 2; i < n; i++ {
							mdata[i] = data[n-(i-n/2)-1]
						}
					case _Sorted:
						for i := 0; i < n; i++ {
							mdata[i] = data[i]
						}
						// Ints is known to be correct
						// because mode Sort runs after mode _Copy.
						Ints(mdata)
					case _Dither:
						for i := 0; i < n; i++ {
							mdata[i] = data[i] + i%5
						}
					}

					desc := fmt.Sprintf("n=%d m=%d dist=%s mode=%s", n, m, dists[dist], modes[mode])
					d := &testingData{desc: desc, t: t, data: mdata[0:n], maxswap: maxswap(n)}
					sort(d)
					// Uncomment if you are trying to improve the number of compares/swaps.
					//t.Logf("%s: ncmp=%d, nswp=%d", desc, d.ncmp, d.nswap)

					// If we were testing C qsort, we'd have to make a copy
					// of the slice and sort it ourselves and then compare
					// x against it, to ensure that qsort was only permuting
					// the data, not (for example) overwriting it with zeros.
					//
					// In go, we don't have to be so paranoid: since the only
					// mutating method Sort can call is TestingData.swap,
					// it suffices here just to check that the final slice is sorted.
					if !IntsAreSorted(mdata) {
						t.Fatalf("%s: ints not sorted\n\t%v", desc, mdata)
					}
				}
			}
		}
	}
}

func TestSortBM(t *testing.T) {
	testBentleyMcIlroy(t, Sort, func(n int) int { return n * lg(n) * 12 / 10 })
}

func TestHeapsortBM(t *testing.T) {
	testBentleyMcIlroy(t, Heapsort, func(n int) int { return n * lg(n) * 12 / 10 })
}

func TestStableBM(t *testing.T) {
	testBentleyMcIlroy(t, Stable, func(n int) int { return n * lg(n) * lg(n) / 3 })
}

// This is based on the "antiquicksort" implementation by M. Douglas McIlroy.
// See https://www.cs.dartmouth.edu/~doug/mdmspe.pdf for more info.
type adversaryTestingData struct {
	t         *testing.T
	data      []int // item values, initialized to special gas value and changed by Less
	maxcmp    int   // number of comparisons allowed
	ncmp      int   // number of comparisons (calls to Less)
	nsolid    int   // number of elements that have been set to non-gas values
	candidate int   // guess at current pivot
	gas       int   // special value for unset elements, higher than everything else
}

func (d *adversaryTestingData) Len() int { return len(d.data) }

func (d *adversaryTestingData) Less(i, j int) bool {
	if d.ncmp >= d.maxcmp {
		d.t.Fatalf("used %d comparisons sorting adversary data with size %d", d.ncmp, len(d.data))
	}
	d.ncmp++

	if d.data[i] == d.gas && d.data[j] == d.gas {
		if i == d.candidate {
			// freeze i
			d.data[i] = d.nsolid
			d.nsolid++
		} else {
			// freeze j
			d.data[j] = d.nsolid
			d.nsolid++
		}
	}

	if d.data[i] == d.gas {
		d.candidate = i
	} else if d.data[j] == d.gas {
		d.candidate = j
	}

	return d.data[i] < d.data[j]
}

func (d *adversaryTestingData) Swap(i, j int) {
	d.data[i], d.data[j] = d.data[j], d.data[i]
}

func newAdversaryTestingData(t *testing.T, size int, maxcmp int) *adversaryTestingData {
	gas := size - 1
	data := make([]int, size)
	for i := 0; i < size; i++ {
		data[i] = gas
	}
	return &adversaryTestingData{t: t, data: data, maxcmp: maxcmp, gas: gas}
}

func TestAdversary(t *testing.T) {
	const size = 10000            // large enough to distinguish between O(n^2) and O(n*log(n))
	maxcmp := size * lg(size) * 4 // the factor 4 was found by trial and error
	d := newAdversaryTestingData(t, size, maxcmp)
	Sort(d) // This should degenerate to heapsort.
	// Check data is fully populated and sorted.
	for i, v := range d.data {
		if v != i {
			t.Fatalf("adversary data not fully sorted")
		}
	}
}

func TestStableInts(t *testing.T) {
	data := ints
	Stable(IntSlice(data[0:]))
	if !IntsAreSorted(data[0:]) {
		t.Errorf("nsorted %v\n   got %v", ints, data)
	}
}

type intPairs []struct {
	a, b int
}

// IntPairs compare on a only.
func (d intPairs) Len() int           { return len(d) }
func (d intPairs) Less(i, j int) bool { return d[i].a < d[j].a }
func (d intPairs) Swap(i, j int)      { d[i], d[j] = d[j], d[i] }

// Record initial order in B.
func (d intPairs) initB() {
	for i := range d {
		d[i].b = i
	}
}

// InOrder checks if a-equal elements were not reordered.
func (d intPairs) inOrder() bool {
	lastA, lastB := -1, 0
	for i := 0; i < len(d); i++ {
		if lastA != d[i].a {
			lastA = d[i].a
			lastB = d[i].b
			continue
		}
		if d[i].b <= lastB {
			return false
		}
		lastB = d[i].b
	}
	return true
}

func TestStability(t *testing.T) {
	n, m := 100000, 1000
	if testing.Short() {
		n, m = 1000, 100
	}
	data := make(intPairs, n)

	// random distribution
	for i := 0; i < len(data); i++ {
		data[i].a = rand.IntN(m)
	}
	if IsSorted(data) {
		t.Fatalf("terrible rand.rand")
	}
	data.initB()
	Stable(data)
	if !IsSorted(data) {
		t.Errorf("Stable didn't sort %d ints", n)
	}
	if !data.inOrder() {
		t.Errorf("Stable wasn't stable on %d ints", n)
	}

	// already sorted
	data.initB()
	Stable(data)
	if !IsSorted(data) {
		t.Errorf("Stable shuffled sorted %d ints (order)", n)
	}
	if !data.inOrder() {
		t.Errorf("Stable shuffled sorted %d ints (stability)", n)
	}

	// sorted reversed
	for i := 0; i < len(data); i++ {
		data[i].a = len(data) - i
	}
	data.initB()
	Stable(data)
	if !IsSorted(data) {
		t.Errorf("Stable didn't sort %d ints", n)
	}
	if !data.inOrder() {
		t.Errorf("Stable wasn't stable on %d ints", n)
	}
}

var countOpsSizes = []int{1e2, 3e2, 1e3, 3e3, 1e4, 3e4, 1e5, 3e5, 1e6}

func countOps(t *testing.T, algo func(Interface), name string) {
	sizes := countOpsSizes
	if testing.Short() {
		sizes = sizes[:5]
	}
	if !testing.Verbose() {
		t.Skip("Counting skipped as non-verbose mode.")
	}
	for _, n := range sizes {
		td := testingData{
			desc:    name,
			t:       t,
			data:    make([]int, n),
			maxswap: 1<<31 - 1,
		}
		for i := 0; i < n; i++ {
			td.data[i] = rand.IntN(n / 5)
		}
		algo(&td)
		t.Logf("%s %8d elements: %11d Swap, %10d Less", name, n, td.nswap, td.ncmp)
	}
}

func TestCountStableOps(t *testing.T) { countOps(t, Stable, "Stable") }
func TestCountSortOps(t *testing.T)   { countOps(t, Sort, "Sort  ") }

func bench(b *testing.B, size int, algo func(Interface), name string) {
	if strings.HasSuffix(testenv.Builder(), "-race") && size > 1e4 {
		b.Skip("skipping slow benchmark on race builder")
	}
	b.StopTimer()
	data := make(intPairs, size)
	x := ^uint32(0)
	for i := 0; i < b.N; i++ {
		for n := size - 3; n <= size+3; n++ {
			for i := 0; i < len(data); i++ {
				x += x
				x ^= 1
				if int32(x) < 0 {
					x ^= 0x88888eef
				}
				data[i].a = int(x % uint32(n/5))
			}
			data.initB()
			b.StartTimer()
			algo(data)
			b.StopTimer()
			if !IsSorted(data) {
				b.Errorf("%s did not sort %d ints", name, n)
			}
			if name == "Stable" && !data.inOrder() {
				b.Errorf("%s unstable on %d ints", name, n)
			}
		}
	}
}

func BenchmarkSort1e2(b *testing.B)   { bench(b, 1e2, Sort, "Sort") }
func BenchmarkStable1e2(b *testing.B) { bench(b, 1e2, Stable, "Stable") }
func BenchmarkSort1e4(b *testing.B)   { bench(b, 1e4, Sort, "Sort") }
func BenchmarkStable1e4(b *testing.B) { bench(b, 1e4, Stable, "Stable") }
func BenchmarkSort1e6(b *testing.B)   { bench(b, 1e6, Sort, "Sort") }
func BenchmarkStable1e6(b *testing.B) { bench(b, 1e6, Stable, "Stable") }

"""



```