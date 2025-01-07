Response:
Let's break down the thought process for analyzing the provided Go code snippet.

1. **Understanding the Request:** The request asks for a functional breakdown of the `sort` package in Go, along with examples, potential pitfalls, and a focus on code inference and command-line arguments (though the latter is less relevant here). The key is to identify *what* the code does and *how* it achieves that.

2. **Initial Scan and High-Level Functionality:**  A quick scan of the code reveals the package name `sort` and immediately suggests its purpose: sorting. The presence of the `Interface` type solidifies this idea, as it defines the contract for sortable collections.

3. **Core Interface Analysis:**  The `Interface` is the heart of the `sort` package. I need to understand its methods:
    * `Len()`: Obvious - returns the number of elements.
    * `Less(i, j int) bool`:  Crucial for comparison logic. The comments explicitly state the requirements for a transitive ordering and the handling of equal elements. The mention of floating-point NaNs is a key detail.
    * `Swap(i, j int)`:  Essential for rearranging elements during the sorting process.

4. **Major Sorting Functions:**  The code defines several sorting functions:
    * `Sort(data Interface)`:  This looks like the main sorting function for any type implementing `Interface`. The comments mention it's not guaranteed to be stable and uses O(n log n) comparisons and swaps. The reference to `slices.SortFunc` is also important to note as a modern alternative.
    * `Stable(data Interface)`:  Clearly a stable sorting algorithm, as its name suggests and the comments confirm. The complexity analysis in the comments is insightful.
    * `Reverse(data Interface)`:  A utility to reverse the order, interesting because it operates on the `Interface`.
    * Convenience functions like `Ints`, `Float64s`, `Strings`, and their `...AreSorted` counterparts. These appear to be wrappers for simpler cases (slices of basic types). The comments about these now calling `slices.Sort` in Go 1.22 are important context.

5. **Helper Types and Functions:**  Beyond the core sorting, I see:
    * `sortedHint`:  Likely used internally for optimization within the `pdqsort` function.
    * `xorshift`: A random number generator, possibly for pivot selection in `pdqsort`.
    * `nextPowerOfTwo`:  A utility for calculating the next power of two, its purpose will become clearer when analyzing `pdqsort`.
    * `lessSwap`:  Seems to be a way to bundle `Less` and `Swap` functions, probably for internal use or code generation.
    * Concrete types like `IntSlice`, `Float64Slice`, `StringSlice`: These are concrete implementations of the `Interface` for common slice types, providing the necessary `Len`, `Less`, and `Swap` methods. The special handling of NaNs in `Float64Slice.Less` is a notable detail.

6. **Internal Sorting Algorithm (pdqsort):** The `Sort` function calls `pdqsort`. This strongly suggests that `pdqsort` is the underlying sorting algorithm used by `Sort`. The `limit` parameter hints at a depth limit, possibly related to recursion in a quicksort-like algorithm.

7. **IsSorted Functionality:** The `IsSorted` function is straightforward – it checks if a given `Interface` is already sorted.

8. **Code Inference and Examples:** Now I need to demonstrate the functionality with examples.
    * **Basic Sorting:**  Start with the simplest case - sorting an `IntSlice`.
    * **Custom Sorting:**  Show how to implement the `Interface` for a custom type. This demonstrates the power and flexibility of the `sort` package. The example of sorting `Person` by age is a good choice.
    * **Stable Sorting:**  Illustrate the difference between `Sort` and `Stable` by showing how the order of equal elements is preserved.
    * **Reverse Sorting:** Demonstrate the use of the `Reverse` function.

9. **Command-Line Arguments:**  The code itself doesn't directly handle command-line arguments. I need to state this explicitly. The `go:generate` comment might be a slight red herring, as it's related to code generation rather than runtime argument parsing.

10. **Common Mistakes:** Think about how users might misuse the `sort` package.
    * **Not implementing the `Interface` correctly:**  Forgetting a method or implementing `Less` incorrectly (not transitive) are potential issues.
    * **Assuming `Sort` is stable:**  This is a critical distinction.
    * **Misunderstanding NaN handling:** The specific behavior of `Float64Slice` needs to be pointed out.

11. **Structuring the Answer:** Organize the information logically:
    * Start with a summary of the package's purpose.
    * Explain the `Interface` in detail.
    * Describe the major sorting functions.
    * Provide code examples.
    * Address command-line arguments.
    * Discuss potential pitfalls.

12. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check that the code examples are correct and easy to understand. Ensure all aspects of the prompt have been addressed. For instance, I initially missed the explicit mention of `slices.Sort` in Go 1.22 in the convenience function comments, so I added that during review. I also double-checked the complexity analysis in the comments for `Stable` to ensure I understood it correctly.

This systematic approach, moving from high-level understanding to detailed analysis and then to practical examples and considerations, allows for a comprehensive and accurate response to the request.
这段代码是 Go 语言标准库 `sort` 包的一部分，它提供了排序切片和用户自定义集合的基本功能。

**功能列表:**

1. **定义了排序接口 `Interface`:**  这是使用 `sort` 包进行排序的核心。任何想要使用 `sort` 包进行排序的数据结构都需要实现这个接口。该接口包含三个方法：
    * `Len() int`: 返回集合中元素的数量。
    * `Less(i, j int) bool`:  判断索引 `i` 的元素是否应该排在索引 `j` 的元素之前。这个方法定义了排序的规则。
    * `Swap(i, j int)`: 交换索引 `i` 和 `j` 的元素。

2. **提供了通用的排序函数 `Sort(data Interface)`:**  这个函数接收任何实现了 `Interface` 的数据结构，并对其进行升序排序。它使用了一种名为 "pdqsort" 的算法，这是一种不稳定的排序算法（即相等元素的相对顺序可能改变）。

3. **提供了稳定排序函数 `Stable(data Interface)`:** 这个函数也接收实现了 `Interface` 的数据结构，并对其进行升序排序，但它会保持相等元素的原始顺序。它使用的算法基于归并排序和块交换旋转。

4. **提供了反转函数 `Reverse(data Interface)`:**  这个函数接收一个 `Interface` 并返回一个新的 `Interface`，该 `Interface` 提供的 `Less` 方法与原始 `Interface` 的 `Less` 方法相反，从而实现降序排序。

5. **提供了判断是否已排序的函数 `IsSorted(data Interface)`:**  接收一个 `Interface`，并返回一个布尔值，指示该数据结构是否已按照 `Less` 方法定义的规则排序。

6. **提供了方便的类型 `IntSlice`, `Float64Slice`, `StringSlice`:**  这些类型分别是对 `[]int`, `[]float64`, `[]string` 的封装，并实现了 `Interface` 接口，使得可以直接对这些类型的切片进行排序。`Float64Slice` 特别处理了 `NaN` (Not a Number) 值，将其排在其他数值之前。

7. **提供了方便的排序函数 `Ints(x []int)`, `Float64s(x []float64)`, `Strings(x []string)`:**  这些函数是对相应类型切片进行排序的便捷方法。**注意：在 Go 1.22 及更高版本中，这些函数实际上只是调用了 `slices` 包中更通用的排序函数。**

8. **提供了方便的判断是否已排序的函数 `IntsAreSorted(x []int)`, `Float64sAreSorted(x []float64)`, `StringsAreSorted(x []string)`:**  这些函数用于检查相应类型的切片是否已排序。**同样，在 Go 1.22 及更高版本中，这些函数实际上只是调用了 `slices` 包中更通用的判断函数。**

**Go 语言功能的实现推理和代码示例:**

这个代码片段主要实现了 Go 语言的 **接口 (interface)** 和 **泛型编程 (通过接口实现)** 的概念。通过定义 `Interface`，`sort` 包可以对任何实现了该接口的类型进行排序，而无需知道其具体的底层数据结构。

**示例 1：对自定义结构体进行排序**

假设我们有一个 `Person` 结构体，我们想要按照年龄对其进行排序。

```go
package main

import (
	"fmt"
	"sort"
)

type Person struct {
	Name string
	Age  int
}

// ByAge 实现了 sort.Interface 以便按年龄排序
type ByAge []Person

func (a ByAge) Len() int           { return len(a) }
func (a ByAge) Less(i, j int) bool { return a[i].Age < a[j].Age }
func (a ByAge) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func main() {
	people := []Person{
		{"Bob", 30},
		{"Alice", 20},
		{"Charlie", 25},
	}

	fmt.Println("排序前:", people)
	sort.Sort(ByAge(people)) // 将 []Person 转换为 ByAge 类型并排序
	fmt.Println("排序后:", people)
}
```

**假设的输入与输出:**

**输入:**

```
people := []Person{
	{"Bob", 30},
	{"Alice", 20},
	{"Charlie", 25},
}
```

**输出:**

```
排序前: [{Bob 30} {Alice 20} {Charlie 25}]
排序后: [{Alice 20} {Charlie 25} {Bob 30}]
```

**示例 2：使用 `sort.Ints` 对整型切片排序**

```go
package main

import (
	"fmt"
	"sort"
)

func main() {
	numbers := []int{5, 2, 8, 1, 9}
	fmt.Println("排序前:", numbers)
	sort.Ints(numbers)
	fmt.Println("排序后:", numbers)
}
```

**假设的输入与输出:**

**输入:**

```
numbers := []int{5, 2, 8, 1, 9}
```

**输出:**

```
排序前: [5 2 8 1 9]
排序后: [1 2 5 8 9]
```

**命令行参数的具体处理:**

这段代码本身并没有直接处理命令行参数。`sort` 包主要提供排序功能，而不是一个独立的命令行工具。 如果你想基于命令行参数来决定排序方式或者输入数据，你需要编写一个使用 `sort` 包的程序，并在该程序中处理命令行参数。

例如，你可以使用 `flag` 包来解析命令行参数，并根据参数选择不同的排序规则或读取不同的输入数据。

```go
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

func main() {
	inputStr := flag.String("input", "", "以逗号分隔的整数列表")
	reverseFlag := flag.Bool("reverse", false, "是否进行降序排序")
	flag.Parse()

	if *inputStr == "" {
		fmt.Println("请使用 -input 参数提供整数列表")
		os.Exit(1)
	}

	strSlice := strings.Split(*inputStr, ",")
	numbers := make([]int, 0, len(strSlice))
	for _, s := range strSlice {
		num, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			fmt.Printf("解析输入错误: %v\n", err)
			os.Exit(1)
		}
		numbers = append(numbers, num)
	}

	fmt.Println("排序前:", numbers)

	if *reverseFlag {
		sort.Sort(sort.Reverse(sort.IntSlice(numbers)))
	} else {
		sort.Ints(numbers)
	}

	fmt.Println("排序后:", numbers)
}
```

**运行示例:**

```bash
go run your_program.go -input "5, 2, 8, 1, 9"
# 输出:
# 排序前: [5 2 8 1 9]
# 排序后: [1 2 5 8 9]

go run your_program.go -input "5, 2, 8, 1, 9" -reverse
# 输出:
# 排序前: [5 2 8 1 9]
# 排序后: [9 8 5 2 1]
```

在这个例子中，我们使用 `flag` 包定义了 `-input` 和 `-reverse` 两个命令行参数，并在程序中根据这些参数来解析输入和决定是否进行降序排序。

**使用者易犯错的点:**

1. **忘记实现 `Interface` 的所有方法:** 如果自定义类型想要使用 `sort.Sort` 或 `sort.Stable`，必须完整地实现 `Len`, `Less`, 和 `Swap` 这三个方法。

   ```go
   // 错误示例：只实现了 Len 和 Less
   type MySlice []int

   func (m MySlice) Len() int           { return len(m) }
   func (m MySlice) Less(i, j int) bool { return m[i] < m[j] }

   func main() {
       mySlice := MySlice{3, 1, 2}
       // sort.Sort(mySlice) // 这会编译错误，因为 MySlice 没有 Swap 方法
   }
   ```

2. **误以为 `sort.Sort` 是稳定的:**  `sort.Sort` 使用的是不稳定的排序算法。如果需要保持相等元素的原始顺序，应该使用 `sort.Stable`。

   ```go
   package main

   import (
       "fmt"
       "sort"
   )

   type Item struct {
       Value int
       Index int
   }

   type ByValue []Item

   func (a ByValue) Len() int           { return len(a) }
   func (a ByValue) Less(i, j int) bool { return a[i].Value < a[j].Value }
   func (a ByValue) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

   func main() {
       items := []Item{{3, 0}, {1, 1}, {3, 2}, {2, 3}}
       fmt.Println("排序前:", items)
       sort.Sort(ByValue(items))
       fmt.Println("使用 sort.Sort 后 (可能不稳定):", items) // 索引 0 和 2 的 Item 顺序可能改变

       items2 := []Item{{3, 0}, {1, 1}, {3, 2}, {2, 3}}
       sort.Stable(ByValue(items2))
       fmt.Println("使用 sort.Stable 后 (稳定):", items2) // 索引 0 的 Item 一定在索引 2 的 Item 前面
   }
   ```

3. **在 `Less` 方法中实现不满足传递性的比较逻辑:** `Less` 方法必须定义一个全序关系，这意味着它必须满足传递性。如果 `Less(a, b)` 和 `Less(b, c)` 都为真，那么 `Less(a, c)` 必须为真。违反传递性会导致排序结果不正确甚至进入无限循环。 尤其需要注意浮点数的比较，因为 `NaN` 的存在，直接使用 `<` 运算符可能不满足传递性，`Float64Slice.Less` 就是一个正确的处理 `NaN` 的例子。

总而言之，`go/src/sort/sort.go` 文件定义了 Go 语言中进行排序操作的核心接口和算法，通过接口实现了对不同类型数据的通用排序功能，并提供了方便的工具函数来简化常见类型的排序操作。 理解 `Interface` 的作用和 `sort.Sort` 与 `sort.Stable` 的区别是使用这个包的关键。

Prompt: 
```
这是路径为go/src/sort/sort.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:generate go run gen_sort_variants.go

// Package sort provides primitives for sorting slices and user-defined collections.
package sort

import (
	"math/bits"
	"slices"
)

// An implementation of Interface can be sorted by the routines in this package.
// The methods refer to elements of the underlying collection by integer index.
type Interface interface {
	// Len is the number of elements in the collection.
	Len() int

	// Less reports whether the element with index i
	// must sort before the element with index j.
	//
	// If both Less(i, j) and Less(j, i) are false,
	// then the elements at index i and j are considered equal.
	// Sort may place equal elements in any order in the final result,
	// while Stable preserves the original input order of equal elements.
	//
	// Less must describe a transitive ordering:
	//  - if both Less(i, j) and Less(j, k) are true, then Less(i, k) must be true as well.
	//  - if both Less(i, j) and Less(j, k) are false, then Less(i, k) must be false as well.
	//
	// Note that floating-point comparison (the < operator on float32 or float64 values)
	// is not a transitive ordering when not-a-number (NaN) values are involved.
	// See Float64Slice.Less for a correct implementation for floating-point values.
	Less(i, j int) bool

	// Swap swaps the elements with indexes i and j.
	Swap(i, j int)
}

// Sort sorts data in ascending order as determined by the Less method.
// It makes one call to data.Len to determine n and O(n*log(n)) calls to
// data.Less and data.Swap. The sort is not guaranteed to be stable.
//
// Note: in many situations, the newer [slices.SortFunc] function is more
// ergonomic and runs faster.
func Sort(data Interface) {
	n := data.Len()
	if n <= 1 {
		return
	}
	limit := bits.Len(uint(n))
	pdqsort(data, 0, n, limit)
}

type sortedHint int // hint for pdqsort when choosing the pivot

const (
	unknownHint sortedHint = iota
	increasingHint
	decreasingHint
)

// xorshift paper: https://www.jstatsoft.org/article/view/v008i14/xorshift.pdf
type xorshift uint64

func (r *xorshift) Next() uint64 {
	*r ^= *r << 13
	*r ^= *r >> 7
	*r ^= *r << 17
	return uint64(*r)
}

func nextPowerOfTwo(length int) uint {
	shift := uint(bits.Len(uint(length)))
	return uint(1 << shift)
}

// lessSwap is a pair of Less and Swap function for use with the
// auto-generated func-optimized variant of sort.go in
// zfuncversion.go.
type lessSwap struct {
	Less func(i, j int) bool
	Swap func(i, j int)
}

type reverse struct {
	// This embedded Interface permits Reverse to use the methods of
	// another Interface implementation.
	Interface
}

// Less returns the opposite of the embedded implementation's Less method.
func (r reverse) Less(i, j int) bool {
	return r.Interface.Less(j, i)
}

// Reverse returns the reverse order for data.
func Reverse(data Interface) Interface {
	return &reverse{data}
}

// IsSorted reports whether data is sorted.
//
// Note: in many situations, the newer [slices.IsSortedFunc] function is more
// ergonomic and runs faster.
func IsSorted(data Interface) bool {
	n := data.Len()
	for i := n - 1; i > 0; i-- {
		if data.Less(i, i-1) {
			return false
		}
	}
	return true
}

// Convenience types for common cases

// IntSlice attaches the methods of Interface to []int, sorting in increasing order.
type IntSlice []int

func (x IntSlice) Len() int           { return len(x) }
func (x IntSlice) Less(i, j int) bool { return x[i] < x[j] }
func (x IntSlice) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

// Sort is a convenience method: x.Sort() calls Sort(x).
func (x IntSlice) Sort() { Sort(x) }

// Float64Slice implements Interface for a []float64, sorting in increasing order,
// with not-a-number (NaN) values ordered before other values.
type Float64Slice []float64

func (x Float64Slice) Len() int { return len(x) }

// Less reports whether x[i] should be ordered before x[j], as required by the sort Interface.
// Note that floating-point comparison by itself is not a transitive relation: it does not
// report a consistent ordering for not-a-number (NaN) values.
// This implementation of Less places NaN values before any others, by using:
//
//	x[i] < x[j] || (math.IsNaN(x[i]) && !math.IsNaN(x[j]))
func (x Float64Slice) Less(i, j int) bool { return x[i] < x[j] || (isNaN(x[i]) && !isNaN(x[j])) }
func (x Float64Slice) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

// isNaN is a copy of math.IsNaN to avoid a dependency on the math package.
func isNaN(f float64) bool {
	return f != f
}

// Sort is a convenience method: x.Sort() calls Sort(x).
func (x Float64Slice) Sort() { Sort(x) }

// StringSlice attaches the methods of Interface to []string, sorting in increasing order.
type StringSlice []string

func (x StringSlice) Len() int           { return len(x) }
func (x StringSlice) Less(i, j int) bool { return x[i] < x[j] }
func (x StringSlice) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

// Sort is a convenience method: x.Sort() calls Sort(x).
func (x StringSlice) Sort() { Sort(x) }

// Convenience wrappers for common cases

// Ints sorts a slice of ints in increasing order.
//
// Note: as of Go 1.22, this function simply calls [slices.Sort].
func Ints(x []int) { slices.Sort(x) }

// Float64s sorts a slice of float64s in increasing order.
// Not-a-number (NaN) values are ordered before other values.
//
// Note: as of Go 1.22, this function simply calls [slices.Sort].
func Float64s(x []float64) { slices.Sort(x) }

// Strings sorts a slice of strings in increasing order.
//
// Note: as of Go 1.22, this function simply calls [slices.Sort].
func Strings(x []string) { slices.Sort(x) }

// IntsAreSorted reports whether the slice x is sorted in increasing order.
//
// Note: as of Go 1.22, this function simply calls [slices.IsSorted].
func IntsAreSorted(x []int) bool { return slices.IsSorted(x) }

// Float64sAreSorted reports whether the slice x is sorted in increasing order,
// with not-a-number (NaN) values before any other values.
//
// Note: as of Go 1.22, this function simply calls [slices.IsSorted].
func Float64sAreSorted(x []float64) bool { return slices.IsSorted(x) }

// StringsAreSorted reports whether the slice x is sorted in increasing order.
//
// Note: as of Go 1.22, this function simply calls [slices.IsSorted].
func StringsAreSorted(x []string) bool { return slices.IsSorted(x) }

// Notes on stable sorting:
// The used algorithms are simple and provable correct on all input and use
// only logarithmic additional stack space. They perform well if compared
// experimentally to other stable in-place sorting algorithms.
//
// Remarks on other algorithms evaluated:
//  - GCC's 4.6.3 stable_sort with merge_without_buffer from libstdc++:
//    Not faster.
//  - GCC's __rotate for block rotations: Not faster.
//  - "Practical in-place mergesort" from  Jyrki Katajainen, Tomi A. Pasanen
//    and Jukka Teuhola; Nordic Journal of Computing 3,1 (1996), 27-40:
//    The given algorithms are in-place, number of Swap and Assignments
//    grow as n log n but the algorithm is not stable.
//  - "Fast Stable In-Place Sorting with O(n) Data Moves" J.I. Munro and
//    V. Raman in Algorithmica (1996) 16, 115-160:
//    This algorithm either needs additional 2n bits or works only if there
//    are enough different elements available to encode some permutations
//    which have to be undone later (so not stable on any input).
//  - All the optimal in-place sorting/merging algorithms I found are either
//    unstable or rely on enough different elements in each step to encode the
//    performed block rearrangements. See also "In-Place Merging Algorithms",
//    Denham Coates-Evely, Department of Computer Science, Kings College,
//    January 2004 and the references in there.
//  - Often "optimal" algorithms are optimal in the number of assignments
//    but Interface has only Swap as operation.

// Stable sorts data in ascending order as determined by the Less method,
// while keeping the original order of equal elements.
//
// It makes one call to data.Len to determine n, O(n*log(n)) calls to
// data.Less and O(n*log(n)*log(n)) calls to data.Swap.
//
// Note: in many situations, the newer slices.SortStableFunc function is more
// ergonomic and runs faster.
func Stable(data Interface) {
	stable(data, data.Len())
}

/*
Complexity of Stable Sorting


Complexity of block swapping rotation

Each Swap puts one new element into its correct, final position.
Elements which reach their final position are no longer moved.
Thus block swapping rotation needs |u|+|v| calls to Swaps.
This is best possible as each element might need a move.

Pay attention when comparing to other optimal algorithms which
typically count the number of assignments instead of swaps:
E.g. the optimal algorithm of Dudzinski and Dydek for in-place
rotations uses O(u + v + gcd(u,v)) assignments which is
better than our O(3 * (u+v)) as gcd(u,v) <= u.


Stable sorting by SymMerge and BlockSwap rotations

SymMerg complexity for same size input M = N:
Calls to Less:  O(M*log(N/M+1)) = O(N*log(2)) = O(N)
Calls to Swap:  O((M+N)*log(M)) = O(2*N*log(N)) = O(N*log(N))

(The following argument does not fuzz over a missing -1 or
other stuff which does not impact the final result).

Let n = data.Len(). Assume n = 2^k.

Plain merge sort performs log(n) = k iterations.
On iteration i the algorithm merges 2^(k-i) blocks, each of size 2^i.

Thus iteration i of merge sort performs:
Calls to Less  O(2^(k-i) * 2^i) = O(2^k) = O(2^log(n)) = O(n)
Calls to Swap  O(2^(k-i) * 2^i * log(2^i)) = O(2^k * i) = O(n*i)

In total k = log(n) iterations are performed; so in total:
Calls to Less O(log(n) * n)
Calls to Swap O(n + 2*n + 3*n + ... + (k-1)*n + k*n)
   = O((k/2) * k * n) = O(n * k^2) = O(n * log^2(n))


Above results should generalize to arbitrary n = 2^k + p
and should not be influenced by the initial insertion sort phase:
Insertion sort is O(n^2) on Swap and Less, thus O(bs^2) per block of
size bs at n/bs blocks:  O(bs*n) Swaps and Less during insertion sort.
Merge sort iterations start at i = log(bs). With t = log(bs) constant:
Calls to Less O((log(n)-t) * n + bs*n) = O(log(n)*n + (bs-t)*n)
   = O(n * log(n))
Calls to Swap O(n * log^2(n) - (t^2+t)/2*n) = O(n * log^2(n))

*/

"""



```