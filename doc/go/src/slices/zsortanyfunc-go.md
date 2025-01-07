Response:
Let's break down the thought process for analyzing the provided Go code.

1. **Understand the Request:** The request asks for a breakdown of the provided Go code snippet, specifically focusing on its functionality, the Go feature it implements, example usage, potential command-line argument handling (though it's unlikely for this low-level sorting code), and common mistakes users might make. Crucially, it specifies using *Chinese* for the answer.

2. **Initial Code Scan - Identifying Core Functionality:**  The first thing to notice is the consistent naming pattern: `...CmpFunc`. This strongly suggests these functions are related to comparison-based sorting algorithms. The presence of functions like `insertionSortCmpFunc`, `heapSortCmpFunc`, `pdqsortCmpFunc`, `partitionCmpFunc`, `symMergeCmpFunc`, and `rotateCmpFunc` reinforces this. The `cmp func(a, b E) int` argument in each function confirms that these are generic sorting implementations accepting a custom comparison function.

3. **Inferring the Go Feature:** The use of generics (`[E any]`) and the passing of a comparison function as an argument are key indicators of implementing a *generic sorting mechanism* in Go. This allows sorting slices of any type, as long as a way to compare elements of that type is provided.

4. **Detailed Function Analysis (Mental Walkthrough):**

   * **`insertionSortCmpFunc`:**  Clearly an implementation of insertion sort. The nested loops and swapping logic are characteristic of this algorithm.
   * **`siftDownCmpFunc`:**  The name and the logic involving `2*root + 1` strongly suggest this is part of a heap-based algorithm, specifically the "sift down" operation to maintain the heap property.
   * **`heapSortCmpFunc`:** Builds on `siftDownCmpFunc`. The initial loop builds the heap, and the subsequent loop extracts elements in sorted order.
   * **`pdqsortCmpFunc`:** The comment explicitly mentions "pattern-defeating quicksort (pdqsort)". This is the main sorting algorithm. The code includes logic for fallback to heapsort, pivot selection, partitioning, and handling potentially sorted or nearly sorted slices.
   * **`partitionCmpFunc`:** Implements the partitioning step of quicksort, placing elements smaller than the pivot to the left and larger to the right.
   * **`partitionEqualCmpFunc`:**  A specialized partition for cases with many equal elements.
   * **`partialInsertionSortCmpFunc`:** Aims to handle nearly sorted slices efficiently.
   * **`breakPatternsCmpFunc`:** An optimization within pdqsort to avoid worst-case scenarios by introducing some randomness.
   * **`choosePivotCmpFunc`:** Selects a pivot element for quicksort, using different strategies based on slice size (static, median-of-three, Tukey ninther).
   * **`order2CmpFunc`, `medianCmpFunc`, `medianAdjacentCmpFunc`:** Helper functions for pivot selection.
   * **`reverseRangeCmpFunc`, `swapRangeCmpFunc`:** Utility functions for manipulating slice elements.
   * **`stableCmpFunc`:**  Implements a *stable* sorting algorithm using a merge sort approach with insertion sort for small blocks.
   * **`symMergeCmpFunc`:** The core merge function for `stableCmpFunc`.
   * **`rotateCmpFunc`:** A utility for rotating sections of the slice, used in `symMergeCmpFunc`.

5. **Example Usage (Go Code):**  To demonstrate the functionality, create a simple example that uses one of the sorting functions. `pdqsortCmpFunc` is the most interesting one. Need to:
    * Define a slice of a specific type (e.g., `[]int`).
    * Create a comparison function for that type.
    * Call `pdqsortCmpFunc` with the slice, bounds, and the comparison function.

6. **Command-Line Arguments:** Review the code. There's no direct interaction with command-line arguments. State this explicitly.

7. **Common Mistakes:** Think about how a user might misuse this code. The primary source of error would be in the comparison function:
    * **Incorrect comparison logic:** Not implementing a strict weak ordering (transitivity, asymmetry).
    * **Inconsistent comparison:**  Returning different results for the same inputs at different times (though less likely in a pure function).
    * **Comparison of incompatible types:**  If the generic type `E` isn't handled correctly in the comparison function.

8. **Structuring the Answer (in Chinese):** Organize the information logically, following the request's structure. Use clear and concise language. Translate technical terms accurately.

9. **Review and Refine:**  Read through the generated Chinese answer to ensure accuracy, clarity, and completeness. Check for any grammatical errors or awkward phrasing. Ensure all parts of the original request have been addressed. For instance, initially, I might forget to explicitly mention the lack of command-line arguments. A review step would catch this.

This detailed process of code scanning, inference, analysis, example creation, and error consideration allows for a comprehensive and accurate understanding of the provided Go code and helps in generating a well-structured answer in the requested language.
这段代码是 Go 语言 `slices` 包中用于实现**泛型排序**功能的一部分。更具体地说，它实现了一系列基于比较函数的排序算法，这些算法可以用于对任何类型的切片进行排序，只要提供了比较两个元素的函数。

**功能列表:**

1. **`insertionSortCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int)`:** 使用插入排序算法对切片 `data` 的子切片 `data[a:b]` 进行排序。它接受一个比较函数 `cmp`，用于确定两个元素的前后顺序。
2. **`siftDownCmpFunc[E any](data []E, lo, hi, first int, cmp func(a, b E) int)`:**  用于实现堆排序的向下调整（sift-down）操作。它维护了切片 `data` 在指定范围内的堆属性，也需要一个比较函数 `cmp`。
3. **`heapSortCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int)`:**  使用堆排序算法对切片 `data` 的子切片 `data[a:b]` 进行排序，同样依赖比较函数 `cmp`。
4. **`pdqsortCmpFunc[E any](data []E, a, b, limit int, cmp func(a, b E) int)`:**  实现了 Pattern-Defeating Quicksort (pdqsort) 算法，这是一种快速且通常比标准快速排序更健壮的排序算法。它也接受一个比较函数 `cmp` 和一个 `limit` 参数，用于控制在回退到堆排序之前的坏枢轴选择次数。
5. **`partitionCmpFunc[E any](data []E, a, b, pivot int, cmp func(a, b E) int)`:**  实现了快速排序的 partition 操作，将切片 `data` 的子切片 `data[a:b]` 分区，使得小于枢轴的元素位于枢轴之前，大于等于枢轴的元素位于枢轴之后。
6. **`partitionEqualCmpFunc[E any](data []E, a, b, pivot int, cmp func(a, b E) int)`:**  用于处理存在大量重复元素的情况，将切片 `data[a:b]` 分区为等于枢轴的元素和大于枢轴的元素两部分。
7. **`partialInsertionSortCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int) bool`:**  对切片进行部分插入排序，用于优化已经部分排序的切片。如果排序完成后切片已完全排序，则返回 `true`。
8. **`breakPatternsCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int)`:**  在 pdqsort 中用于打乱部分元素，以避免某些可能导致分区不平衡的模式。
9. **`choosePivotCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int) (pivot int, hint sortedHint)`:**  在 pdqsort 中选择枢轴元素。它使用了不同的策略，例如 median-of-three 和 Tukey ninther，并返回枢轴的索引以及关于切片排序状态的提示。
10. **`order2CmpFunc[E any](data []E, a, b int, swaps *int, cmp func(a, b E) int) (int, int)`:**  辅助函数，用于比较两个元素并返回它们的有序索引。
11. **`medianCmpFunc[E any](data []E, a, b, c int, swaps *int, cmp func(a, b E) int) int`:**  辅助函数，返回三个元素的中位数的索引。
12. **`medianAdjacentCmpFunc[E any](data []E, a int, swaps *int, cmp func(a, b E) int) int`:** 辅助函数，返回相邻三个元素的中位数的索引。
13. **`reverseRangeCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int)`:**  反转切片 `data` 的子切片 `data[a:b]`。
14. **`swapRangeCmpFunc[E any](data []E, a, b, n int, cmp func(a, b E) int)`:**  交换切片中两个相邻的长度为 `n` 的子切片。
15. **`stableCmpFunc[E any](data []E, n int, cmp func(a, b E) int)`:**  实现稳定的归并排序算法，保证相等元素的相对顺序在排序后不变。
16. **`symMergeCmpFunc[E any](data []E, a, m, b int, cmp func(a, b E) int)`:**  `stableCmpFunc` 使用的对称归并算法。
17. **`rotateCmpFunc[E any](data []E, a, m, b int, cmp func(a, b E) int)`:**  用于在 `symMergeCmpFunc` 中旋转切片元素的辅助函数。

**推理 Go 语言功能：**

这段代码是 Go 语言中实现**泛型排序**功能的底层实现。Go 1.18 引入了泛型，允许编写可以处理多种类型的代码，而无需为每种类型都编写重复的代码。在这里，泛型被用来实现排序算法，这些算法可以用于任何类型的切片，只要提供了比较函数。

**Go 代码示例：**

```go
package main

import (
	"fmt"
	"slices"
)

type Person struct {
	Name string
	Age  int
}

func main() {
	people := []Person{
		{"Bob", 30},
		{"Alice", 25},
		{"Charlie", 35},
	}

	// 使用自定义比较函数按年龄排序
	slices.SortFunc(people, func(a, b Person) int {
		return a.Age - b.Age
	})
	fmt.Println("按年龄排序:", people)

	// 使用自定义比较函数按姓名排序
	slices.SortFunc(people, func(a, b Person) int {
		if a.Name < b.Name {
			return -1
		} else if a.Name > b.Name {
			return 1
		}
		return 0
	})
	fmt.Println("按姓名排序:", people)
}
```

**假设的输入与输出：**

在上面的代码示例中：

**第一次排序（按年龄）：**

* **假设输入:**
  ```
  people := []Person{
    {"Bob", 30},
    {"Alice", 25},
    {"Charlie", 35},
  }
  ```
* **输出:**
  ```
  按年龄排序: [{Alice 25} {Bob 30} {Charlie 35}]
  ```

**第二次排序（按姓名）：**

* **假设输入:**  （注意，这里的输入是上一次排序后的结果）
  ```
  people := []Person{
    {"Alice", 25},
    {"Bob", 30},
    {"Charlie", 35},
  }
  ```
* **输出:**
  ```
  按姓名排序: [{Alice 25} {Bob 30} {Charlie 35}]
  ```

**命令行参数处理：**

这段代码本身并没有直接处理命令行参数。它是一个底层的排序算法实现，通常被 `slices` 包中的 `SortFunc` 等更高级的函数调用。如果需要通过命令行参数来控制排序行为（例如，指定排序字段或排序顺序），则需要在调用 `slices.SortFunc` 的上层代码中进行处理。

**使用者易犯错的点：**

1. **比较函数逻辑错误：**  使用者提供的比较函数 `cmp func(a, b E) int` 必须满足严格弱序关系。这意味着：
   * 如果 `cmp(a, b) < 0`，则 `a` 应该在 `b` 之前。
   * 如果 `cmp(b, a) < 0`，则 `b` 应该在 `a` 之前。
   * 如果 `cmp(a, b) == 0` 且 `cmp(b, a) == 0`，则 `a` 和 `b` 被认为是相等的。
   * 传递性：如果 `cmp(a, b) < 0` 且 `cmp(b, c) < 0`，则 `cmp(a, c)` 必须小于 0。

   **示例错误：** 假设我们想要按年龄排序，但比较函数写成了：

   ```go
   slices.SortFunc(people, func(a, b Person) int {
       return a.Age - b.Age // 如果 a.Age == b.Age，返回 0，看似没问题
   })
   ```

   虽然这个例子在大多数情况下能正常工作，但在某些复杂的排序场景下，严格弱序的细微差别可能会导致问题。更稳妥的写法是：

   ```go
   slices.SortFunc(people, func(a, b Person) int {
       if a.Age < b.Age {
           return -1
       } else if a.Age > b.Age {
           return 1
       }
       return 0
   })
   ```

2. **比较不可比较的类型：**  如果尝试使用这段代码对无法比较的类型（例如包含函数的结构体）的切片进行排序，将会导致编译错误，除非提供了合适的比较函数。

总而言之，这段代码是 Go 语言泛型排序的核心实现，提供了一系列高效且灵活的排序算法，使用者可以通过提供自定义的比较函数来对任意类型的切片进行排序。理解比较函数的正确实现是使用此功能时需要注意的关键点。

Prompt: 
```
这是路径为go/src/slices/zsortanyfunc.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。

"""
// Code generated by gen_sort_variants.go; DO NOT EDIT.

// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package slices

// insertionSortCmpFunc sorts data[a:b] using insertion sort.
func insertionSortCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int) {
	for i := a + 1; i < b; i++ {
		for j := i; j > a && (cmp(data[j], data[j-1]) < 0); j-- {
			data[j], data[j-1] = data[j-1], data[j]
		}
	}
}

// siftDownCmpFunc implements the heap property on data[lo:hi].
// first is an offset into the array where the root of the heap lies.
func siftDownCmpFunc[E any](data []E, lo, hi, first int, cmp func(a, b E) int) {
	root := lo
	for {
		child := 2*root + 1
		if child >= hi {
			break
		}
		if child+1 < hi && (cmp(data[first+child], data[first+child+1]) < 0) {
			child++
		}
		if !(cmp(data[first+root], data[first+child]) < 0) {
			return
		}
		data[first+root], data[first+child] = data[first+child], data[first+root]
		root = child
	}
}

func heapSortCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int) {
	first := a
	lo := 0
	hi := b - a

	// Build heap with greatest element at top.
	for i := (hi - 1) / 2; i >= 0; i-- {
		siftDownCmpFunc(data, i, hi, first, cmp)
	}

	// Pop elements, largest first, into end of data.
	for i := hi - 1; i >= 0; i-- {
		data[first], data[first+i] = data[first+i], data[first]
		siftDownCmpFunc(data, lo, i, first, cmp)
	}
}

// pdqsortCmpFunc sorts data[a:b].
// The algorithm based on pattern-defeating quicksort(pdqsort), but without the optimizations from BlockQuicksort.
// pdqsort paper: https://arxiv.org/pdf/2106.05123.pdf
// C++ implementation: https://github.com/orlp/pdqsort
// Rust implementation: https://docs.rs/pdqsort/latest/pdqsort/
// limit is the number of allowed bad (very unbalanced) pivots before falling back to heapsort.
func pdqsortCmpFunc[E any](data []E, a, b, limit int, cmp func(a, b E) int) {
	const maxInsertion = 12

	var (
		wasBalanced    = true // whether the last partitioning was reasonably balanced
		wasPartitioned = true // whether the slice was already partitioned
	)

	for {
		length := b - a

		if length <= maxInsertion {
			insertionSortCmpFunc(data, a, b, cmp)
			return
		}

		// Fall back to heapsort if too many bad choices were made.
		if limit == 0 {
			heapSortCmpFunc(data, a, b, cmp)
			return
		}

		// If the last partitioning was imbalanced, we need to breaking patterns.
		if !wasBalanced {
			breakPatternsCmpFunc(data, a, b, cmp)
			limit--
		}

		pivot, hint := choosePivotCmpFunc(data, a, b, cmp)
		if hint == decreasingHint {
			reverseRangeCmpFunc(data, a, b, cmp)
			// The chosen pivot was pivot-a elements after the start of the array.
			// After reversing it is pivot-a elements before the end of the array.
			// The idea came from Rust's implementation.
			pivot = (b - 1) - (pivot - a)
			hint = increasingHint
		}

		// The slice is likely already sorted.
		if wasBalanced && wasPartitioned && hint == increasingHint {
			if partialInsertionSortCmpFunc(data, a, b, cmp) {
				return
			}
		}

		// Probably the slice contains many duplicate elements, partition the slice into
		// elements equal to and elements greater than the pivot.
		if a > 0 && !(cmp(data[a-1], data[pivot]) < 0) {
			mid := partitionEqualCmpFunc(data, a, b, pivot, cmp)
			a = mid
			continue
		}

		mid, alreadyPartitioned := partitionCmpFunc(data, a, b, pivot, cmp)
		wasPartitioned = alreadyPartitioned

		leftLen, rightLen := mid-a, b-mid
		balanceThreshold := length / 8
		if leftLen < rightLen {
			wasBalanced = leftLen >= balanceThreshold
			pdqsortCmpFunc(data, a, mid, limit, cmp)
			a = mid + 1
		} else {
			wasBalanced = rightLen >= balanceThreshold
			pdqsortCmpFunc(data, mid+1, b, limit, cmp)
			b = mid
		}
	}
}

// partitionCmpFunc does one quicksort partition.
// Let p = data[pivot]
// Moves elements in data[a:b] around, so that data[i]<p and data[j]>=p for i<newpivot and j>newpivot.
// On return, data[newpivot] = p
func partitionCmpFunc[E any](data []E, a, b, pivot int, cmp func(a, b E) int) (newpivot int, alreadyPartitioned bool) {
	data[a], data[pivot] = data[pivot], data[a]
	i, j := a+1, b-1 // i and j are inclusive of the elements remaining to be partitioned

	for i <= j && (cmp(data[i], data[a]) < 0) {
		i++
	}
	for i <= j && !(cmp(data[j], data[a]) < 0) {
		j--
	}
	if i > j {
		data[j], data[a] = data[a], data[j]
		return j, true
	}
	data[i], data[j] = data[j], data[i]
	i++
	j--

	for {
		for i <= j && (cmp(data[i], data[a]) < 0) {
			i++
		}
		for i <= j && !(cmp(data[j], data[a]) < 0) {
			j--
		}
		if i > j {
			break
		}
		data[i], data[j] = data[j], data[i]
		i++
		j--
	}
	data[j], data[a] = data[a], data[j]
	return j, false
}

// partitionEqualCmpFunc partitions data[a:b] into elements equal to data[pivot] followed by elements greater than data[pivot].
// It assumed that data[a:b] does not contain elements smaller than the data[pivot].
func partitionEqualCmpFunc[E any](data []E, a, b, pivot int, cmp func(a, b E) int) (newpivot int) {
	data[a], data[pivot] = data[pivot], data[a]
	i, j := a+1, b-1 // i and j are inclusive of the elements remaining to be partitioned

	for {
		for i <= j && !(cmp(data[a], data[i]) < 0) {
			i++
		}
		for i <= j && (cmp(data[a], data[j]) < 0) {
			j--
		}
		if i > j {
			break
		}
		data[i], data[j] = data[j], data[i]
		i++
		j--
	}
	return i
}

// partialInsertionSortCmpFunc partially sorts a slice, returns true if the slice is sorted at the end.
func partialInsertionSortCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int) bool {
	const (
		maxSteps         = 5  // maximum number of adjacent out-of-order pairs that will get shifted
		shortestShifting = 50 // don't shift any elements on short arrays
	)
	i := a + 1
	for j := 0; j < maxSteps; j++ {
		for i < b && !(cmp(data[i], data[i-1]) < 0) {
			i++
		}

		if i == b {
			return true
		}

		if b-a < shortestShifting {
			return false
		}

		data[i], data[i-1] = data[i-1], data[i]

		// Shift the smaller one to the left.
		if i-a >= 2 {
			for j := i - 1; j >= 1; j-- {
				if !(cmp(data[j], data[j-1]) < 0) {
					break
				}
				data[j], data[j-1] = data[j-1], data[j]
			}
		}
		// Shift the greater one to the right.
		if b-i >= 2 {
			for j := i + 1; j < b; j++ {
				if !(cmp(data[j], data[j-1]) < 0) {
					break
				}
				data[j], data[j-1] = data[j-1], data[j]
			}
		}
	}
	return false
}

// breakPatternsCmpFunc scatters some elements around in an attempt to break some patterns
// that might cause imbalanced partitions in quicksort.
func breakPatternsCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int) {
	length := b - a
	if length >= 8 {
		random := xorshift(length)
		modulus := nextPowerOfTwo(length)

		for idx := a + (length/4)*2 - 1; idx <= a+(length/4)*2+1; idx++ {
			other := int(uint(random.Next()) & (modulus - 1))
			if other >= length {
				other -= length
			}
			data[idx], data[a+other] = data[a+other], data[idx]
		}
	}
}

// choosePivotCmpFunc chooses a pivot in data[a:b].
//
// [0,8): chooses a static pivot.
// [8,shortestNinther): uses the simple median-of-three method.
// [shortestNinther,∞): uses the Tukey ninther method.
func choosePivotCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int) (pivot int, hint sortedHint) {
	const (
		shortestNinther = 50
		maxSwaps        = 4 * 3
	)

	l := b - a

	var (
		swaps int
		i     = a + l/4*1
		j     = a + l/4*2
		k     = a + l/4*3
	)

	if l >= 8 {
		if l >= shortestNinther {
			// Tukey ninther method, the idea came from Rust's implementation.
			i = medianAdjacentCmpFunc(data, i, &swaps, cmp)
			j = medianAdjacentCmpFunc(data, j, &swaps, cmp)
			k = medianAdjacentCmpFunc(data, k, &swaps, cmp)
		}
		// Find the median among i, j, k and stores it into j.
		j = medianCmpFunc(data, i, j, k, &swaps, cmp)
	}

	switch swaps {
	case 0:
		return j, increasingHint
	case maxSwaps:
		return j, decreasingHint
	default:
		return j, unknownHint
	}
}

// order2CmpFunc returns x,y where data[x] <= data[y], where x,y=a,b or x,y=b,a.
func order2CmpFunc[E any](data []E, a, b int, swaps *int, cmp func(a, b E) int) (int, int) {
	if cmp(data[b], data[a]) < 0 {
		*swaps++
		return b, a
	}
	return a, b
}

// medianCmpFunc returns x where data[x] is the median of data[a],data[b],data[c], where x is a, b, or c.
func medianCmpFunc[E any](data []E, a, b, c int, swaps *int, cmp func(a, b E) int) int {
	a, b = order2CmpFunc(data, a, b, swaps, cmp)
	b, c = order2CmpFunc(data, b, c, swaps, cmp)
	a, b = order2CmpFunc(data, a, b, swaps, cmp)
	return b
}

// medianAdjacentCmpFunc finds the median of data[a - 1], data[a], data[a + 1] and stores the index into a.
func medianAdjacentCmpFunc[E any](data []E, a int, swaps *int, cmp func(a, b E) int) int {
	return medianCmpFunc(data, a-1, a, a+1, swaps, cmp)
}

func reverseRangeCmpFunc[E any](data []E, a, b int, cmp func(a, b E) int) {
	i := a
	j := b - 1
	for i < j {
		data[i], data[j] = data[j], data[i]
		i++
		j--
	}
}

func swapRangeCmpFunc[E any](data []E, a, b, n int, cmp func(a, b E) int) {
	for i := 0; i < n; i++ {
		data[a+i], data[b+i] = data[b+i], data[a+i]
	}
}

func stableCmpFunc[E any](data []E, n int, cmp func(a, b E) int) {
	blockSize := 20 // must be > 0
	a, b := 0, blockSize
	for b <= n {
		insertionSortCmpFunc(data, a, b, cmp)
		a = b
		b += blockSize
	}
	insertionSortCmpFunc(data, a, n, cmp)

	for blockSize < n {
		a, b = 0, 2*blockSize
		for b <= n {
			symMergeCmpFunc(data, a, a+blockSize, b, cmp)
			a = b
			b += 2 * blockSize
		}
		if m := a + blockSize; m < n {
			symMergeCmpFunc(data, a, m, n, cmp)
		}
		blockSize *= 2
	}
}

// symMergeCmpFunc merges the two sorted subsequences data[a:m] and data[m:b] using
// the SymMerge algorithm from Pok-Son Kim and Arne Kutzner, "Stable Minimum
// Storage Merging by Symmetric Comparisons", in Susanne Albers and Tomasz
// Radzik, editors, Algorithms - ESA 2004, volume 3221 of Lecture Notes in
// Computer Science, pages 714-723. Springer, 2004.
//
// Let M = m-a and N = b-n. Wolog M < N.
// The recursion depth is bound by ceil(log(N+M)).
// The algorithm needs O(M*log(N/M + 1)) calls to data.Less.
// The algorithm needs O((M+N)*log(M)) calls to data.Swap.
//
// The paper gives O((M+N)*log(M)) as the number of assignments assuming a
// rotation algorithm which uses O(M+N+gcd(M+N)) assignments. The argumentation
// in the paper carries through for Swap operations, especially as the block
// swapping rotate uses only O(M+N) Swaps.
//
// symMerge assumes non-degenerate arguments: a < m && m < b.
// Having the caller check this condition eliminates many leaf recursion calls,
// which improves performance.
func symMergeCmpFunc[E any](data []E, a, m, b int, cmp func(a, b E) int) {
	// Avoid unnecessary recursions of symMerge
	// by direct insertion of data[a] into data[m:b]
	// if data[a:m] only contains one element.
	if m-a == 1 {
		// Use binary search to find the lowest index i
		// such that data[i] >= data[a] for m <= i < b.
		// Exit the search loop with i == b in case no such index exists.
		i := m
		j := b
		for i < j {
			h := int(uint(i+j) >> 1)
			if cmp(data[h], data[a]) < 0 {
				i = h + 1
			} else {
				j = h
			}
		}
		// Swap values until data[a] reaches the position before i.
		for k := a; k < i-1; k++ {
			data[k], data[k+1] = data[k+1], data[k]
		}
		return
	}

	// Avoid unnecessary recursions of symMerge
	// by direct insertion of data[m] into data[a:m]
	// if data[m:b] only contains one element.
	if b-m == 1 {
		// Use binary search to find the lowest index i
		// such that data[i] > data[m] for a <= i < m.
		// Exit the search loop with i == m in case no such index exists.
		i := a
		j := m
		for i < j {
			h := int(uint(i+j) >> 1)
			if !(cmp(data[m], data[h]) < 0) {
				i = h + 1
			} else {
				j = h
			}
		}
		// Swap values until data[m] reaches the position i.
		for k := m; k > i; k-- {
			data[k], data[k-1] = data[k-1], data[k]
		}
		return
	}

	mid := int(uint(a+b) >> 1)
	n := mid + m
	var start, r int
	if m > mid {
		start = n - b
		r = mid
	} else {
		start = a
		r = m
	}
	p := n - 1

	for start < r {
		c := int(uint(start+r) >> 1)
		if !(cmp(data[p-c], data[c]) < 0) {
			start = c + 1
		} else {
			r = c
		}
	}

	end := n - start
	if start < m && m < end {
		rotateCmpFunc(data, start, m, end, cmp)
	}
	if a < start && start < mid {
		symMergeCmpFunc(data, a, start, mid, cmp)
	}
	if mid < end && end < b {
		symMergeCmpFunc(data, mid, end, b, cmp)
	}
}

// rotateCmpFunc rotates two consecutive blocks u = data[a:m] and v = data[m:b] in data:
// Data of the form 'x u v y' is changed to 'x v u y'.
// rotate performs at most b-a many calls to data.Swap,
// and it assumes non-degenerate arguments: a < m && m < b.
func rotateCmpFunc[E any](data []E, a, m, b int, cmp func(a, b E) int) {
	i := m - a
	j := b - m

	for i != j {
		if i > j {
			swapRangeCmpFunc(data, m-i, m, j, cmp)
			i -= j
		} else {
			swapRangeCmpFunc(data, m-i, m+j-i, i, cmp)
			j -= i
		}
	}
	// i == j
	swapRangeCmpFunc(data, m-i, m, i, cmp)
}

"""



```