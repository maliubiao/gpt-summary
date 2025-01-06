Response: Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The file name `intervals_test.go` immediately signals that this is a testing file. The package name `liveness` and the function names like `TestIntervalOverlap`, `TestIntervalsMerge`, etc., strongly suggest this code is about managing and testing operations on intervals, likely related to "liveness analysis" in a compiler.

2. **Examine `TestMain`:** This function is standard for Go test files. It parses flags and runs the tests. The key takeaway here is the presence of flags, which hints at configurable test behavior.

3. **Analyze Individual Test Functions:**  Go through each `Test` function systematically:
    * **`TestMakeAndPrint`:**  This seems to test the creation of `Intervals` from a slice of integers and their string representation. The test cases cover valid intervals, errors like odd number of elements, bad ranges (end <= start), overlaps, and out-of-order starts. This tells us about the expected input format for creating intervals and the error handling.
    * **`TestIntervalOverlap`:**  Focuses on testing the `Overlaps` method of a single `Interval`. The test cases illustrate different overlap scenarios (exact match, no overlap, partial overlap).
    * **`TestIntervalAdjacent`:** Tests the `adjacent` method. The examples show cases where intervals touch and don't touch.
    * **`TestIntervalMerge`:** Tests the `MergeInto` method, modifying an interval to include another. Crucially, it checks for errors when merging non-adjacent/non-overlapping intervals and handles cases of same, adjacent, and overlapping intervals.
    * **`TestIntervalsOverlap`:**  Tests the `Overlaps` method for a collection of `Intervals`. It explores scenarios with empty sets, disjoint sets, and interleaved sets.
    * **`TestRandomIntervalsOverlap`:**  This is interesting. It uses random number generation to create intervals and then tests the `Overlaps` method against a "brute-force" implementation. This suggests a more robust test for correctness under various random conditions. The presence of flags like `seed`, `trials`, `segs`, and `limit` points to configurable random testing.
    * **`TestIntervalsMerge`:** Tests merging two `Intervals` objects into a new `Intervals` object. It handles cases with empty sets, overlapping sets, and non-overlapping sets.
    * **`TestBuilder`:** This test focuses on a builder pattern (`IntervalsBuilder`). It simulates adding "live" and "kill" events at specific positions and verifies the resulting `Intervals`. This hints at how liveness information is incrementally constructed.

4. **Identify Helper Functions and Data Structures:**
    * **`Interval`:**  The presence of methods like `Overlaps`, `adjacent`, `MergeInto`, and `String` strongly indicates a struct named `Interval` likely with `st` (start) and `en` (end) fields.
    * **`Intervals`:** The fact that `makeIntervals` returns an `Intervals` and the `Overlaps` and `Merge` methods are called on it suggests `Intervals` is likely a slice of `Interval`. The `String` method on `Intervals` further supports this.
    * **`IntervalsBuilder`:** This is clearly a builder pattern used for constructing `Intervals` incrementally based on "live" and "kill" events.
    * **`makeIntervals`:**  This function is specifically for creating `Intervals` from a flat slice of integers. It includes error checking for odd numbers of elements and invalid ranges.
    * **`check`:**  While not directly tested, the call to `check(r)` in `makeIntervals` hints at a function for validating the created `Intervals` object, likely ensuring sorted and non-overlapping intervals.

5. **Infer Functionality and Purpose:** Based on the tests and the file path (`go/src/cmd/compile/internal/liveness/`), it's reasonable to infer that this code implements and tests a data structure (`Intervals`) for representing the live ranges of variables or values during the compilation process. Liveness analysis is a crucial optimization technique in compilers.

6. **Construct Example Usage (Mental Model):** Imagine a variable `x` being defined at some point and used until another point. This live range can be represented by an `Interval`. The `Intervals` type allows representing multiple such non-overlapping live ranges for a single entity. The `IntervalsBuilder` provides a way to build these live ranges by processing events like when a variable becomes live (defined) and when it's no longer needed (killed).

7. **Address Specific Questions:**
    * **Functionality:** List the tested functionalities (creation, overlap checks, merging, building).
    * **Go Feature:**  Infer liveness analysis and provide a basic example of variable live ranges.
    * **Code Inference:**  Describe the structure of `Interval` and `Intervals` with assumed fields. Explain the purpose of `makeIntervals` and `IntervalsBuilder`. Provide example input and expected output for key functions like `makeIntervals`, `Overlaps`, and `Merge`.
    * **Command-line Arguments:** Detail the flags used for random testing (`seed`, `trials`, `segs`, `limit`).
    * **Common Mistakes:**  Focus on the error conditions tested in `TestMakeAndPrint` as potential pitfalls for users of `makeIntervals`.

This structured approach, combining code examination with domain knowledge (compiler optimization in this case), allows for a comprehensive understanding of the code's functionality and its role within the larger system.
这是 Go 语言 `cmd/compile/internal/liveness` 包中 `intervals_test.go` 文件的一部分，它主要用于测试 `intervals.go` 文件中实现的关于 **生命周期区间 (liveness intervals)** 的功能。

**功能列表:**

1. **`TestMakeAndPrint`**: 测试创建 `Intervals` 对象以及将其转换为字符串表示的功能。它涵盖了创建有效区间、退化区间以及各种错误情况（例如，奇数个输入元素、非法区间范围、区间重叠、区间起始点未排序）。
2. **`TestIntervalOverlap`**: 测试单个 `Interval` 对象的 `Overlaps` 方法，判断两个区间是否重叠。
3. **`TestIntervalAdjacent`**: 测试单个 `Interval` 对象的 `adjacent` 方法，判断两个区间是否相邻（即一个区间的结束点是另一个区间的起始点）。
4. **`TestIntervalMerge`**: 测试单个 `Interval` 对象的 `MergeInto` 方法，将一个区间合并到另一个区间中。它涵盖了合并相同区间、相邻区间、重叠区间以及尝试合并不相邻/不重叠区间时产生的错误。
5. **`TestIntervalsOverlap`**: 测试 `Intervals` 对象（一组区间）的 `Overlaps` 方法，判断两个 `Intervals` 对象是否存在任何重叠的区间。
6. **`TestRandomIntervalsOverlap`**: 使用随机生成的区间来更广泛地测试 `Intervals` 对象的 `Overlaps` 方法，并与一个简单的暴力算法进行比较，以验证其正确性。
7. **`TestIntervalsMerge`**: 测试 `Intervals` 对象的 `Merge` 方法，将两个 `Intervals` 对象合并成一个新的 `Intervals` 对象，合并重叠或相邻的区间。
8. **`TestBuilder`**: 测试 `IntervalsBuilder` 的功能。`IntervalsBuilder` 允许逐步构建 `Intervals` 对象，通过添加 "live" (变量开始活跃) 和 "kill" (变量不再活跃) 的事件来定义区间。

**Go 语言功能实现推断 (生命周期分析相关):**

这段代码很可能是编译器中用于实现**生命周期分析 (Liveness Analysis)** 的一部分。生命周期分析是一种编译器优化技术，用于确定程序中每个变量在哪些代码点是活跃的（即其值可能在后续被使用）。 这些活跃的时间段可以用区间来表示。

**Go 代码举例说明:**

假设我们有如下简单的 Go 代码片段：

```go
package main

func main() {
	a := 10 // 变量 a 开始活跃
	b := a + 5
	println(b)
	c := 20 // 变量 c 开始活跃
	println(c)
	// 变量 a 和 b 不再被使用，它们的生命周期结束
	d := c * 2 // 变量 d 开始活跃
	println(d)
	// 变量 c 和 d 不再被使用
}
```

使用 `liveness` 包中的 `Intervals` 可能将变量的生命周期表示为：

* 变量 `a`: 从定义 `a := 10` 到 `println(b)` 之后。假设代码位置是离散的，例如 `[0, 2)`.
* 变量 `b`: 从定义 `b := a + 5` 到 `println(b)` 之后。例如 `[1, 2)`.
* 变量 `c`: 从定义 `c := 20` 到 `println(c)` 之后。例如 `[3, 4)`.
* 变量 `d`: 从定义 `d := c * 2` 到 `println(d)` 之后。例如 `[5, 6)`.

`intervals_test.go` 中的测试代码就是在验证如何创建、比较和操作这些生命周期区间。例如，`TestIntervalOverlap` 可以用来检查两个变量的生命周期是否在任何时间点重叠，这对于寄存器分配等优化非常重要。

**代码推理与假设的输入输出:**

**假设 `Interval` 结构体定义如下：**

```go
type Interval struct {
	st int // 起始位置
	en int // 结束位置 (不包含)
}

func (i Interval) String() string {
	return fmt.Sprintf("[%d,%d)", i.st, i.en)
}

func (i Interval) Overlaps(other Interval) bool {
	return i.st < other.en && other.st < i.en
}

func (i Interval) adjacent(other Interval) bool {
	return i.en == other.st || other.en == i.st
}

func (i *Interval) MergeInto(other Interval) error {
	if !i.Overlaps(other) && !i.adjacent(other) {
		return fmt.Errorf("cannot merge non-overlapping/non-adjacent intervals")
	}
	if other.st < i.st {
		i.st = other.st
	}
	if other.en > i.en {
		i.en = other.en
	}
	return nil
}

type Intervals []Interval

func (is Intervals) String() string {
	var s string
	for _, i := range is {
		s += i.String() + " "
	}
	return s[:len(s)-1]
}

func (is Intervals) Overlaps(other Intervals) bool {
	for _, i1 := range is {
		for _, i2 := range other {
			if i1.Overlaps(i2) {
				return true
			}
		}
	}
	return false
}

func (is Intervals) Merge(other Intervals) Intervals {
	merged := make(Intervals, len(is)+len(other))
	copy(merged, is)
	copy(merged[len(is):], other)
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].st < merged[j].st
	})

	if len(merged) <= 1 {
		return merged
	}

	result := make(Intervals, 0, len(merged))
	current := merged[0]
	for i := 1; i < len(merged); i++ {
		if current.Overlaps(merged[i]) || current.adjacent(merged[i]) {
			current.MergeInto(merged[i])
		} else {
			result = append(result, current)
			current = merged[i]
		}
	}
	result = append(result, current)
	return result
}

type IntervalsBuilder struct {
	intervals Intervals
	currentStart int
	building bool
}

func (b *IntervalsBuilder) Live(pos int) error {
	if pos < 0 {
		return fmt.Errorf("position cannot be negative")
	}
	if b.building && pos <= b.currentStart {
		return fmt.Errorf("position should be increasing")
	}
	if !b.building {
		b.currentStart = pos
		b.building = true
	}
	return nil
}

func (b *IntervalsBuilder) Kill(pos int) error {
	if pos < 0 {
		return fmt.Errorf("position cannot be negative")
	}
	if !b.building || pos < b.currentStart {
		return fmt.Errorf("kill position before live position")
	}
	b.intervals = append(b.intervals, Interval{st: b.currentStart, en: pos + 1})
	b.building = false
	return nil
}

func (b *IntervalsBuilder) Finish() (Intervals, error) {
	if b.building {
		return nil, fmt.Errorf("unfinished interval")
	}
	return b.intervals, nil
}

func makeIntervals(nums ...int) (Intervals, error) {
	var r Intervals
	if len(nums)&1 != 0 {
		return r, fmt.Errorf("odd number of elems %d", len(nums))
	}
	for i := 0; i < len(nums); i += 2 {
		st := nums[i]
		en := nums[i+1]
		r = append(r, Interval{st: st, en: en})
	}
	sort.Slice(r, func(i, j int) bool {
		return r[i].st < r[j].st
	})
	// 简单的检查，实际中可能更复杂
	for i := 1; i < len(r); i++ {
		if r[i].st < r[i-1].en {
			return nil, fmt.Errorf("intervals overlap")
		}
	}
	return r, nil
}

func check(is Intervals) error {
	for i := 1; i < len(is); i++ {
		if is[i].st < is[i-1].en {
			return fmt.Errorf("intervals overlap or not sorted")
		}
	}
	return nil
}
```

**`TestMakeAndPrint` 示例:**

* **输入:** `inp: []int{0, 1, 2, 3}`
* **输出:**  创建 `Intervals` 对象 `{[0,1), [2,3)}`，其字符串表示为 `"[0,1) [2,3)"`

* **输入:** `inp: []int{0, 0}`
* **输出:** 错误，因为区间结束位置不大于起始位置，错误信息为 `"bad range elem 0:0, en<=st"`

**`TestIntervalOverlap` 示例:**

* **输入:** `i1: Interval{st: 0, en: 1}`, `i2: Interval{st: 0, en: 1}`
* **输出:** `true` (区间完全重叠)

* **输入:** `i1: Interval{st: 0, en: 1}`, `i2: Interval{st: 1, en: 2}`
* **输出:** `false` (区间相邻但不重叠)

**`TestIntervalsOverlap` 示例:**

* **输入:** `inp1: []int{1, 3}`, `inp2: []int{2, 9, 10, 11}`
* **输出:** 创建 `is1: {[1,3)}` 和 `is2: {[2,9), [10,11)}`，然后 `is1.Overlaps(is2)` 返回 `true`，因为 `[1,3)` 与 `[2,9)` 重叠。

**`TestIntervalsMerge` 示例:**

* **输入:** `inp1: []int{1, 2}`, `inp2: []int{2, 3}`
* **输出:** 创建 `is1: {[1,2)}` 和 `is2: {[2,3)}`，然后 `is1.Merge(is2)` 返回 `{[1,3)}`。

**`TestBuilder` 示例:**

* **输入:** `inp: []posLiveKill{ {pos: 10, becomesLive: true}, {pos: 9, isKill: true} }`
* **输出:** 错误，因为 `Kill` 事件的位置 `9` 小于之前的 `Live` 事件的位置 `10`。

* **输入:** `inp: []posLiveKill{ {pos: 10, becomesLive: true}, {pos: 11, isKill: true} }`
* **输出:** 创建的 `Intervals` 对象为 `{[10,12)}` (假设代码位置是离散的，`Kill` 在位置 `11` 意味着区间到 `12` 结束)。

**命令行参数的具体处理:**

`TestMain` 函数中调用了 `flag.Parse()`，这意味着这个测试文件支持一些命令行参数。从代码中可以看出定义的 flag：

* **`-seed int64`**:  用于 `TestRandomIntervalsOverlap` 中的随机数生成器的种子。这允许在多次运行测试时获得相同的随机序列，方便复现问题。默认值为 `101`。
* **`-trials int64`**:  在 `TestRandomIntervalsOverlap` 中执行的随机测试的次数。默认值为 `10000`。
* **`-segs int64`**:  在 `TestRandomIntervalsOverlap` 中生成的随机区间对象中，最大的区间段数量。默认值为 `4`。
* **`-limit int64`**:  在 `TestRandomIntervalsOverlap` 中生成的随机区间的最大结束值。默认值为 `20`。

**使用方法:**

在命令行运行测试时，可以指定这些参数来控制随机测试的行为：

```bash
go test -seed=12345 -trials=5000 -segs=3 ./intervals_test.go
```

这将使用种子 `12345` 运行 `5000` 次随机测试，并且生成的区间对象最多包含 `3` 个区间段。

**使用者易犯错的点:**

1. **使用 `makeIntervals` 时提供奇数个参数:**  `makeIntervals` 期望接收成对的起始和结束位置。提供奇数个参数会导致错误，例如：
   ```go
   _, err := makeIntervals(1, 2, 3) // 错误：奇数个参数
   ```
   错误信息会是 `"odd number of elems 3"`。

2. **在 `makeIntervals` 中提供非法区间范围 (结束位置不大于起始位置):**  区间的结束位置必须严格大于起始位置，否则会导致错误，例如：
   ```go
   _, err := makeIntervals(1, 1) // 错误：结束位置等于起始位置
   ```
   错误信息会是 `"bad range elem 1:1, en<=st"`。

3. **在 `makeIntervals` 中提供重叠的区间:**  `makeIntervals` 期望接收一组不重叠且起始位置已排序的区间。提供重叠的区间会导致错误，例如：
   ```go
   _, err := makeIntervals(1, 3, 2, 4) // 错误：[1,3) 和 [2,4) 重叠
   ```
   错误信息会是 `"bad range elem 2:4 overlaps prev 1:3"`。

4. **在 `makeIntervals` 中提供的区间起始位置未排序:** 区间的起始位置必须按升序排列，否则会导致错误，例如：
   ```go
   _, err := makeIntervals(3, 4, 1, 2) // 错误：[1,2) 的起始位置小于前一个区间
   ```
   错误信息会是 `"range start not ordered 1:2 less than prev 3:4"`。

5. **`IntervalsBuilder` 的使用顺序错误:**  必须先调用 `Live` 标记变量开始活跃，然后调用 `Kill` 标记变量不再活跃。如果在 `Live` 之前调用 `Kill`，或者 `Kill` 的位置小于对应的 `Live` 位置，都会导致错误。例如：
   ```go
   var builder IntervalsBuilder
   err := builder.Kill(5) // 错误：在 Live 之前调用 Kill
   ```
   ```go
   var builder IntervalsBuilder
   builder.Live(10)
   err := builder.Kill(9) // 错误：Kill 的位置小于 Live 的位置
   ```
   `IntervalsBuilder` 旨在按时间顺序处理生命周期事件。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/liveness/intervals_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package liveness

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(m.Run())
}

func TestMakeAndPrint(t *testing.T) {
	testcases := []struct {
		inp []int
		exp string
		err bool
	}{
		{
			inp: []int{0, 1, 2, 3},
			exp: "[0,1) [2,3)",
		},
		{ // degenerate but legal
			inp: []int{0, 1, 1, 2},
			exp: "[0,1) [1,2)",
		},
		{ // odd number of elems
			inp: []int{0},
			err: true,
			exp: "odd number of elems 1",
		},
		{
			// bad range element
			inp: []int{0, 0},
			err: true,
			exp: "bad range elem 0:0, en<=st",
		},
		{
			// overlap w/ previous
			inp: []int{0, 9, 3, 12},
			err: true,
			exp: "bad range elem 3:12 overlaps prev 0:9",
		},
		{
			// range starts not ordered
			inp: []int{10, 11, 3, 4},
			err: true,
			exp: "range start not ordered 3:4 less than prev 10:11",
		},
	}

	for k, tc := range testcases {
		is, err := makeIntervals(tc.inp...)
		want := tc.exp
		if err != nil {
			if !tc.err {
				t.Fatalf("unexpected error on tc:%d %+v -> %v", k, tc.inp, err)
			} else {
				got := fmt.Sprintf("%v", err)
				if got != want {
					t.Fatalf("bad error on tc:%d %+v got %q want %q", k, tc.inp, got, want)
				}
			}
			continue
		} else if tc.err {
			t.Fatalf("missing error on tc:%d %+v return was %q", k, tc.inp, is.String())
		}
		got := is.String()
		if got != want {
			t.Fatalf("exp mismatch on tc:%d %+v got %q want %q", k, tc.inp, got, want)
		}
	}
}

func TestIntervalOverlap(t *testing.T) {
	testcases := []struct {
		i1, i2 Interval
		exp    bool
	}{
		{
			i1:  Interval{st: 0, en: 1},
			i2:  Interval{st: 0, en: 1},
			exp: true,
		},
		{
			i1:  Interval{st: 0, en: 1},
			i2:  Interval{st: 1, en: 2},
			exp: false,
		},
		{
			i1:  Interval{st: 9, en: 10},
			i2:  Interval{st: 1, en: 2},
			exp: false,
		},
		{
			i1:  Interval{st: 0, en: 10},
			i2:  Interval{st: 5, en: 6},
			exp: true,
		},
	}

	for _, tc := range testcases {
		want := tc.exp
		got := tc.i1.Overlaps(tc.i2)
		if want != got {
			t.Fatalf("Overlaps([%d,%d), [%d,%d)): got %v want %v",
				tc.i1.st, tc.i1.en, tc.i2.st, tc.i2.en, got, want)
		}
	}
}

func TestIntervalAdjacent(t *testing.T) {
	testcases := []struct {
		i1, i2 Interval
		exp    bool
	}{
		{
			i1:  Interval{st: 0, en: 1},
			i2:  Interval{st: 0, en: 1},
			exp: false,
		},
		{
			i1:  Interval{st: 0, en: 1},
			i2:  Interval{st: 1, en: 2},
			exp: true,
		},
		{
			i1:  Interval{st: 1, en: 2},
			i2:  Interval{st: 0, en: 1},
			exp: true,
		},
		{
			i1:  Interval{st: 0, en: 10},
			i2:  Interval{st: 0, en: 3},
			exp: false,
		},
	}

	for k, tc := range testcases {
		want := tc.exp
		got := tc.i1.adjacent(tc.i2)
		if want != got {
			t.Fatalf("tc=%d adjacent([%d,%d), [%d,%d)): got %v want %v",
				k, tc.i1.st, tc.i1.en, tc.i2.st, tc.i2.en, got, want)
		}
	}
}

func TestIntervalMerge(t *testing.T) {
	testcases := []struct {
		i1, i2 Interval
		exp    Interval
		err    bool
	}{
		{
			// error case
			i1:  Interval{st: 0, en: 1},
			i2:  Interval{st: 2, en: 3},
			err: true,
		},
		{
			// same
			i1:  Interval{st: 0, en: 1},
			i2:  Interval{st: 0, en: 1},
			exp: Interval{st: 0, en: 1},
			err: false,
		},
		{
			// adjacent
			i1:  Interval{st: 0, en: 1},
			i2:  Interval{st: 1, en: 2},
			exp: Interval{st: 0, en: 2},
			err: false,
		},
		{
			// overlapping 1
			i1:  Interval{st: 0, en: 5},
			i2:  Interval{st: 3, en: 10},
			exp: Interval{st: 0, en: 10},
			err: false,
		},
		{
			// overlapping 2
			i1:  Interval{st: 9, en: 15},
			i2:  Interval{st: 3, en: 11},
			exp: Interval{st: 3, en: 15},
			err: false,
		},
	}

	for k, tc := range testcases {
		var dst Interval
		dstp := &dst
		dst = tc.i1
		err := dstp.MergeInto(tc.i2)
		if (err != nil) != tc.err {
			t.Fatalf("tc=%d MergeInto([%d,%d) <= [%d,%d)): got err=%v want err=%v", k, tc.i1.st, tc.i1.en, tc.i2.st, tc.i2.en, err, tc.err)
		}
		if err != nil {
			continue
		}
		want := tc.exp.String()
		got := dst.String()
		if want != got {
			t.Fatalf("tc=%d MergeInto([%d,%d) <= [%d,%d)): got %v want %v",
				k, tc.i1.st, tc.i1.en, tc.i2.st, tc.i2.en, got, want)
		}
	}
}

func TestIntervalsOverlap(t *testing.T) {
	testcases := []struct {
		inp1, inp2 []int
		exp        bool
	}{
		{
			// first empty
			inp1: []int{},
			inp2: []int{1, 2},
			exp:  false,
		},
		{
			// second empty
			inp1: []int{9, 10},
			inp2: []int{},
			exp:  false,
		},
		{
			// disjoint 1
			inp1: []int{1, 2},
			inp2: []int{2, 3},
			exp:  false,
		},
		{
			// disjoint 2
			inp1: []int{2, 3},
			inp2: []int{1, 2},
			exp:  false,
		},
		{
			// interleaved 1
			inp1: []int{1, 2, 3, 4},
			inp2: []int{2, 3, 5, 6},
			exp:  false,
		},
		{
			// interleaved 2
			inp1: []int{2, 3, 5, 6},
			inp2: []int{1, 2, 3, 4},
			exp:  false,
		},
		{
			// overlap 1
			inp1: []int{1, 3},
			inp2: []int{2, 9, 10, 11},
			exp:  true,
		},
		{
			// overlap 2
			inp1: []int{18, 29},
			inp2: []int{2, 9, 10, 19},
			exp:  true,
		},
	}

	for k, tc := range testcases {
		is1, err1 := makeIntervals(tc.inp1...)
		if err1 != nil {
			t.Fatalf("unexpected error on tc:%d %+v: %v", k, tc.inp1, err1)
		}
		is2, err2 := makeIntervals(tc.inp2...)
		if err2 != nil {
			t.Fatalf("unexpected error on tc:%d %+v: %v", k, tc.inp2, err2)
		}
		got := is1.Overlaps(is2)
		want := tc.exp
		if got != want {
			t.Fatalf("overlaps mismatch on tc:%d %+v %+v got %v want %v", k, tc.inp1, tc.inp2, got, want)
		}
	}
}

var seedflag = flag.Int64("seed", 101, "Random seed")
var trialsflag = flag.Int64("trials", 10000, "Number of trials")
var segsflag = flag.Int64("segs", 4, "Max segments within interval")
var limitflag = flag.Int64("limit", 20, "Limit of interval max end")

// NB: consider turning this into a fuzz test if the interval data
// structures or code get any more complicated.

func TestRandomIntervalsOverlap(t *testing.T) {
	rand.Seed(*seedflag)

	// Return a pseudo-random intervals object with 0-3 segments within
	// the range of 0 to limit
	mk := func() Intervals {
		vals := rand.Perm(int(*limitflag))
		// decide how many segments
		segs := rand.Intn(int(*segsflag))
		picked := vals[:(segs * 2)]
		sort.Ints(picked)
		ii, err := makeIntervals(picked...)
		if err != nil {
			t.Fatalf("makeIntervals(%+v) returns err %v", picked, err)
		}
		return ii
	}

	brute := func(i1, i2 Intervals) bool {
		for i := range i1 {
			for j := range i2 {
				if i1[i].Overlaps(i2[j]) {
					return true
				}
			}
		}
		return false
	}

	for k := range *trialsflag {
		// Create two interval ranges and test if they overlap. Then
		// compare the overlap with a brute-force overlap calculation.
		i1, i2 := mk(), mk()
		got := i1.Overlaps(i2)
		want := brute(i1, i2)
		if got != want {
			t.Fatalf("overlap mismatch on t:%d %v %v got %v want %v",
				k, i1, i2, got, want)
		}
	}
}

func TestIntervalsMerge(t *testing.T) {
	testcases := []struct {
		inp1, inp2 []int
		exp        []int
	}{
		{
			// first empty
			inp1: []int{},
			inp2: []int{1, 2},
			exp:  []int{1, 2},
		},
		{
			// second empty
			inp1: []int{1, 2},
			inp2: []int{},
			exp:  []int{1, 2},
		},
		{
			// overlap 1
			inp1: []int{1, 2},
			inp2: []int{2, 3},
			exp:  []int{1, 3},
		},
		{
			// overlap 2
			inp1: []int{1, 5},
			inp2: []int{2, 10},
			exp:  []int{1, 10},
		},
		{
			// non-overlap 1
			inp1: []int{1, 2},
			inp2: []int{11, 12},
			exp:  []int{1, 2, 11, 12},
		},
		{
			// non-overlap 2
			inp1: []int{1, 2, 3, 4, 5, 6},
			inp2: []int{2, 3, 4, 5, 6, 7},
			exp:  []int{1, 7},
		},
	}

	for k, tc := range testcases {
		is1, err1 := makeIntervals(tc.inp1...)
		if err1 != nil {
			t.Fatalf("unexpected error on tc:%d %+v: %v", k, tc.inp1, err1)
		}
		is2, err2 := makeIntervals(tc.inp2...)
		if err2 != nil {
			t.Fatalf("unexpected error on tc:%d %+v: %v", k, tc.inp2, err2)
		}
		m := is1.Merge(is2)
		wis, werr := makeIntervals(tc.exp...)
		if werr != nil {
			t.Fatalf("unexpected error on tc:%d %+v: %v", k, tc.exp, werr)
		}
		want := wis.String()
		got := m.String()
		if want != got {
			t.Fatalf("k=%d Merge(%s, %s): got %v want %v",
				k, is1, is2, m, want)
		}
	}
}

func TestBuilder(t *testing.T) {
	type posLiveKill struct {
		pos                 int
		becomesLive, isKill bool // what to pass to IntervalsBuilder
	}
	testcases := []struct {
		inp        []posLiveKill
		exp        []int
		aerr, ferr bool
	}{
		// error case, position non-decreasing
		{
			inp: []posLiveKill{
				posLiveKill{pos: 10, becomesLive: true},
				posLiveKill{pos: 18, isKill: true},
			},
			aerr: true,
		},
		// error case, position negative
		{
			inp: []posLiveKill{
				posLiveKill{pos: -1, becomesLive: true},
			},
			aerr: true,
		},
		// empty
		{
			exp: nil,
		},
		// single BB
		{
			inp: []posLiveKill{
				posLiveKill{pos: 10, becomesLive: true},
				posLiveKill{pos: 9, isKill: true},
			},
			exp: []int{10, 11},
		},
		// couple of BBs
		{
			inp: []posLiveKill{
				posLiveKill{pos: 11, becomesLive: true},
				posLiveKill{pos: 10, becomesLive: true},
				posLiveKill{pos: 9, isKill: true},
				posLiveKill{pos: 4, becomesLive: true},
				posLiveKill{pos: 1, isKill: true},
			},
			exp: []int{2, 5, 10, 12},
		},
		// couple of BBs
		{
			inp: []posLiveKill{
				posLiveKill{pos: 20, isKill: true},
				posLiveKill{pos: 19, isKill: true},
				posLiveKill{pos: 17, becomesLive: true},
				posLiveKill{pos: 14, becomesLive: true},
				posLiveKill{pos: 10, isKill: true},
				posLiveKill{pos: 4, becomesLive: true},
				posLiveKill{pos: 0, isKill: true},
			},
			exp: []int{1, 5, 11, 18},
		},
	}

	for k, tc := range testcases {
		var c IntervalsBuilder
		var aerr error
		for _, event := range tc.inp {
			if event.becomesLive {
				if err := c.Live(event.pos); err != nil {
					aerr = err
					break
				}
			}
			if event.isKill {
				if err := c.Kill(event.pos); err != nil {
					aerr = err
					break
				}
			}
		}
		if (aerr != nil) != tc.aerr {
			t.Fatalf("k=%d add err mismatch: tc.aerr:%v aerr!=nil:%v",
				k, tc.aerr, (aerr != nil))
		}
		if tc.aerr {
			continue
		}
		ii, ferr := c.Finish()
		if ferr != nil {
			if tc.ferr {
				continue
			}
			t.Fatalf("h=%d finish err mismatch: tc.ferr:%v ferr!=nil:%v", k, tc.ferr, ferr != nil)
		}
		got := ii.String()
		wis, werr := makeIntervals(tc.exp...)
		if werr != nil {
			t.Fatalf("unexpected error on tc:%d %+v: %v", k, tc.exp, werr)
		}
		want := wis.String()
		if want != got {
			t.Fatalf("k=%d Ctor test: got %v want %v", k, got, want)
		}
	}
}

// makeIntervals constructs an Intervals object from the start/end
// sequence in nums, expected to be of the form
// s1,en1,st2,en2,...,stk,enk. Used only for unit testing.
func makeIntervals(nums ...int) (Intervals, error) {
	var r Intervals
	if len(nums)&1 != 0 {
		return r, fmt.Errorf("odd number of elems %d", len(nums))
	}
	for i := 0; i < len(nums); i += 2 {
		st := nums[i]
		en := nums[i+1]
		r = append(r, Interval{st: st, en: en})
	}
	return r, check(r)
}

"""



```