Response:
Let's break down the thought process to answer the request about the `slices.go` file.

**1. Understanding the Request:**

The core request is to analyze the provided Go code snippet and explain its functionality. The request has several specific sub-points:

* **List Functionality:** Enumerate the distinct operations the code performs on slices.
* **Identify Go Feature:**  Determine what higher-level Go feature this code likely implements or supports.
* **Provide Go Code Examples:** Illustrate the usage of each function with practical examples, including inputs and outputs.
* **Address Code Reasoning:** If any function's behavior requires deeper explanation or has non-obvious logic, provide the reasoning behind it. Include hypothetical inputs and outputs to clarify.
* **Explain Command-Line Arguments:** If any function processes command-line arguments (unlikely in this standard library package), detail how.
* **Highlight Common Mistakes:**  Point out potential pitfalls or errors users might make when using these functions.
* **Use Chinese:** The entire response must be in Chinese.

**2. Initial Code Scan and Function Identification:**

The first step is to read through the code and identify the different functions defined within the `slices` package. This is straightforward as each function has a clear name and doc comment. The identified functions are:

* `Equal`
* `EqualFunc`
* `Compare`
* `CompareFunc`
* `Index`
* `IndexFunc`
* `Contains`
* `ContainsFunc`
* `Insert`
* `Delete`
* `DeleteFunc`
* `Replace`
* `Clone`
* `Compact`
* `CompactFunc`
* `Grow`
* `Clip`
* `Reverse`
* `Concat`
* `Repeat`

**3. Determining the Core Go Feature:**

Based on the function names and their descriptions (from the doc comments), it's evident that this code provides utility functions for working with Go slices. This is the core functionality it implements.

**4. Analyzing Each Function and Generating Examples:**

For each function, the next step is to understand its specific purpose and craft a representative Go code example. This involves:

* **Reading the Doc Comment:** The doc comment provides the most concise description of the function's behavior, parameters, and return value.
* **Considering Different Scenarios:**  Think about common use cases and edge cases for each function. For instance, when testing `Equal`, consider empty slices, slices of different lengths, and slices with equal elements. For `Insert`, consider inserting at the beginning, middle, and end, as well as inserting multiple elements.
* **Choosing Appropriate Data Types:**  Select suitable data types for the slice elements in the examples (e.g., `int`, `string`).
* **Predicting the Output:**  Mentally execute the example code to determine the expected output. This helps in verifying the correctness of the example.
* **Writing the Go Code:**  Construct the Go code snippet, including the `package main`, `import`, `func main`, variable declarations, function calls, and `fmt.Println` for output.

**5. Addressing Code Reasoning (Complex Functions):**

Some functions, like `Insert`, `Delete`, and `Replace`, have more complex logic, particularly around memory management and potential overlaps. For these, a more detailed explanation is needed. This involves:

* **Understanding the Algorithm:** Analyze the code to understand the steps involved in the operation. For `Insert`, pay attention to how it handles capacity and potential overlaps between the inserted elements and the existing slice.
* **Using Diagrams (Mental or Actual):** Visualize the memory layout and how the elements are shifted or copied. The comments in the code itself are very helpful here.
* **Hypothetical Inputs and Outputs:** Create specific scenarios with example inputs and trace the execution to show the intermediate steps and the final output. This clarifies the function's behavior in those specific cases.

**6. Command-Line Arguments and Common Mistakes:**

* **Command-Line Arguments:**  Standard library packages like `slices` typically don't directly handle command-line arguments. This is more common in executable programs. Therefore, for this section, the answer is simply that there are no command-line arguments.
* **Common Mistakes:** Think about common errors developers might make when using slice functions. For example, with `Delete`, a common mistake is to iterate and delete elements without adjusting the loop index, leading to skipping elements. For `Compact`, understanding that it modifies the original slice in place is important.

**7. Translation to Chinese:**

The final step is to translate the entire analysis, examples, and explanations into clear and accurate Chinese. This requires careful attention to terminology and phrasing to ensure the meaning is preserved.

**Self-Correction/Refinement During the Process:**

* **Initial Simplification:**  Sometimes, when first looking at a function, you might oversimplify its purpose. Re-reading the doc comments and the code helps to refine the understanding.
* **Example Clarity:**  Ensure the examples are easy to understand and directly illustrate the function's behavior. If an example is too complex, break it down into simpler ones.
* **Accuracy of Output:** Double-check the predicted output of the examples to avoid errors. Run the code if unsure.
* **Completeness:** Make sure all functions are covered in the explanation.
* **Clarity of Chinese:** Review the Chinese translation for natural flow and correct terminology.

By following these steps systematically, the comprehensive and accurate answer provided earlier can be constructed. The key is to go function by function, understand its purpose, illustrate it with examples, and explain any complex aspects clearly.
这个 `go/src/slices/slices.go` 文件是 Go 语言标准库中 `slices` 包的一部分。它提供了一系列用于操作切片的通用函数，适用于任何类型的切片。

以下是该文件中定义的功能列表以及相关的解释和示例：

**1. `Equal[S ~[]E, E comparable](s1, s2 S) bool`:**

* **功能:**  判断两个切片 `s1` 和 `s2` 是否相等。相等意味着它们具有相同的长度，并且所有对应位置的元素都相等。
* **Go 语言功能:** 这是对切片进行深度比较的基本操作。Go 语言的 `==` 运算符在切片上只会比较引用地址，而不会比较元素的值。`Equal` 函数提供了基于值的比较。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s1 := []int{1, 2, 3}
	s2 := []int{1, 2, 3}
	s3 := []int{1, 2, 4}
	s4 := []int{1, 2}

	fmt.Println(slices.Equal(s1, s2)) // Output: true
	fmt.Println(slices.Equal(s1, s3)) // Output: false
	fmt.Println(slices.Equal(s1, s4)) // Output: false
	fmt.Println(slices.Equal(nil, []int{})) // Output: true
}
```

**2. `EqualFunc[S1 ~[]E1, S2 ~[]E2, E1, E2 any](s1 S1, s2 S2, eq func(E1, E2) bool) bool`:**

* **功能:**  判断两个切片 `s1` 和 `s2` 是否相等，使用一个自定义的相等性判断函数 `eq` 来比较元素。
* **Go 语言功能:**  提供了更灵活的切片比较方式，允许用户自定义元素相等的逻辑。例如，比较字符串时忽略大小写。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
	"strings"
)

func main() {
	s1 := []string{"hello", "world"}
	s2 := []string{"HELLO", "WORLD"}

	equalIgnoreCase := func(s1, s2 string) bool {
		return strings.ToLower(s1) == strings.ToLower(s2)
	}

	fmt.Println(slices.EqualFunc(s1, s2, equalIgnoreCase)) // Output: true
}
```

**3. `Compare[S ~[]E, E cmp.Ordered](s1, s2 S) int`:**

* **功能:**  比较两个切片 `s1` 和 `s2` 的元素，使用 `cmp.Compare` 函数对每个元素对进行比较。
* **Go 语言功能:**  提供了切片的比较功能，类似于字符串的比较。可以用于排序等场景。
* **代码示例:**

```go
package main

import (
	"cmp"
	"fmt"
	"slices"
)

func main() {
	s1 := []int{1, 2, 3}
	s2 := []int{1, 2, 3}
	s3 := []int{1, 2, 4}
	s4 := []int{1, 2}

	fmt.Println(slices.Compare(s1, s2)) // Output: 0
	fmt.Println(slices.Compare(s1, s3)) // Output: -1
	fmt.Println(slices.Compare(s3, s1)) // Output: 1
	fmt.Println(slices.Compare(s1, s4)) // Output: 1
	fmt.Println(slices.Compare(s4, s1)) // Output: -1
}
```

**4. `CompareFunc[S1 ~[]E1, S2 ~[]E2, E1, E2 any](s1 S1, s2 S2, cmp func(E1, E2) int) int`:**

* **功能:**  比较两个切片 `s1` 和 `s2` 的元素，使用自定义的比较函数 `cmp`。
* **Go 语言功能:**  提供了更灵活的切片比较方式，允许用户自定义元素比较的逻辑。
* **代码示例:**  类似于 `EqualFunc`，可以自定义比较逻辑。

**5. `Index[S ~[]E, E comparable](s S, v E) int`:**

* **功能:**  返回元素 `v` 在切片 `s` 中第一次出现的索引，如果不存在则返回 -1。
* **Go 语言功能:**  实现了切片的查找功能。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := []int{10, 20, 30, 20}
	fmt.Println(slices.Index(s, 20)) // Output: 1
	fmt.Println(slices.Index(s, 40)) // Output: -1
}
```

**6. `IndexFunc[S ~[]E, E any](s S, f func(E) bool) int`:**

* **功能:**  返回切片 `s` 中第一个满足条件 `f(s[i])` 的元素的索引，如果不存在则返回 -1。
* **Go 语言功能:**  提供了基于条件查找切片元素的功能。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := []int{10, 21, 30, 25}
	isOdd := func(n int) bool { return n%2 != 0 }
	fmt.Println(slices.IndexFunc(s, isOdd)) // Output: 1
}
```

**7. `Contains[S ~[]E, E comparable](s S, v E) bool`:**

* **功能:**  判断切片 `s` 是否包含元素 `v`。
* **Go 语言功能:**  简单的判断元素是否存在于切片中。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := []int{1, 2, 3}
	fmt.Println(slices.Contains(s, 2)) // Output: true
	fmt.Println(slices.Contains(s, 4)) // Output: false
}
```

**8. `ContainsFunc[S ~[]E, E any](s S, f func(E) bool) bool`:**

* **功能:**  判断切片 `s` 中是否存在至少一个元素满足条件 `f(e)`。
* **Go 语言功能:**  基于条件判断切片中是否存在符合条件的元素。
* **代码示例:**  类似于 `IndexFunc` 的示例，只是返回布尔值。

**9. `Insert[S ~[]E, E any](s S, i int, v ...E) S`:**

* **功能:**  在切片 `s` 的索引 `i` 处插入元素 `v`，返回修改后的切片。
* **Go 语言功能:**  提供了在指定位置插入元素的功能。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := []int{1, 2, 3}
	s = slices.Insert(s, 1, 4, 5)
	fmt.Println(s) // Output: [1 4 5 2 3]
}
```
* **代码推理:** `Insert` 函数会创建一个新的切片，将 `s[:i]` 的元素复制到新切片，然后将要插入的元素 `v` 复制到新切片，最后将 `s[i:]` 的元素复制到新切片。如果插入后超出原切片的容量，会重新分配内存。
    * **假设输入:** `s = []int{1, 2, 3}`, `i = 1`, `v = []int{4, 5}`
    * **输出:** `[]int{1, 4, 5, 2, 3}`

**10. `Delete[S ~[]E, E any](s S, i, j int) S`:**

* **功能:**  删除切片 `s` 中索引从 `i` 到 `j-1` 的元素，返回修改后的切片。
* **Go 语言功能:**  提供了删除切片中一段连续元素的功能。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := []int{1, 2, 3, 4, 5}
	s = slices.Delete(s, 1, 3)
	fmt.Println(s) // Output: [1 4 5]
}
```

**11. `DeleteFunc[S ~[]E, E any](s S, del func(E) bool) S`:**

* **功能:**  删除切片 `s` 中所有满足条件 `del(e)` 的元素，返回修改后的切片。
* **Go 语言功能:**  提供了基于条件删除切片元素的功能。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := []int{1, 2, 3, 4, 5, 6}
	isEven := func(n int) bool { return n%2 == 0 }
	s = slices.DeleteFunc(s, isEven)
	fmt.Println(s) // Output: [1 3 5]
}
```

**12. `Replace[S ~[]E, E any](s S, i, j int, v ...E) S`:**

* **功能:**  将切片 `s` 中索引从 `i` 到 `j-1` 的元素替换为 `v`，返回修改后的切片。
* **Go 语言功能:**  提供了替换切片中一段连续元素的功能。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := []int{1, 2, 3, 4, 5}
	s = slices.Replace(s, 1, 3, 6, 7)
	fmt.Println(s) // Output: [1 6 7 4 5]
}
```
* **代码推理:** `Replace` 函数的处理方式取决于替换后的长度是否超过原切片的容量。如果未超过，它可能会在原切片上进行修改。如果超过，则会创建一个新的切片。
    * **假设输入:** `s = []int{1, 2, 3, 4, 5}`, `i = 1`, `j = 3`, `v = []int{6, 7}`
    * **输出:** `[]int{1, 6, 7, 4, 5}`

**13. `Clone[S ~[]E, E any](s S) S`:**

* **功能:**  返回切片 `s` 的一个副本。这是一个浅拷贝，即复制的是元素的值，如果元素本身是引用类型，则复制的是引用。
* **Go 语言功能:**  创建切片的独立副本，避免修改副本影响原始切片。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s1 := []int{1, 2, 3}
	s2 := slices.Clone(s1)
	s2[0] = 10
	fmt.Println(s1) // Output: [1 2 3]
	fmt.Println(s2) // Output: [10 2 3]
}
```

**14. `Compact[S ~[]E, E comparable](s S) S`:**

* **功能:**  移除切片 `s` 中连续重复的元素，只保留第一次出现的元素。修改原始切片并返回修改后的切片。
* **Go 语言功能:**  类似于 Unix 的 `uniq` 命令。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := []int{1, 1, 2, 2, 2, 3, 1}
	s = slices.Compact(s)
	fmt.Println(s) // Output: [1 2 3 1]
}
```

**15. `CompactFunc[S ~[]E, E any](s S, eq func(E, E) bool) S`:**

* **功能:**  类似于 `Compact`，但使用自定义的相等性判断函数 `eq` 来比较元素是否重复。
* **Go 语言功能:**  提供了更灵活的去重方式。
* **代码示例:**  类似于 `EqualFunc` 的示例，用于自定义比较逻辑。

**16. `Grow[S ~[]E, E any](s S, n int) S`:**

* **功能:**  增加切片 `s` 的容量，以保证至少可以再容纳 `n` 个元素。如果 `n` 为负数或过大导致无法分配内存，则会 panic。
* **Go 语言功能:**  手动控制切片的容量，避免频繁的内存重新分配。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := make([]int, 0, 3)
	fmt.Println(cap(s)) // Output: 3
	s = slices.Grow(s, 5)
	fmt.Println(cap(s)) // Output: 8 (容量会增长，具体增长策略可能不同)
}
```

**17. `Clip[S ~[]E, E any](s S) S`:**

* **功能:**  移除切片 `s` 未使用的容量，返回一个长度和容量相等的切片。
* **Go 语言功能:**  释放切片占用的多余内存。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := make([]int, 3, 10)
	fmt.Println(len(s), cap(s)) // Output: 3 10
	s = slices.Clip(s)
	fmt.Println(len(s), cap(s)) // Output: 3 3
}
```

**18. `Reverse[S ~[]E, E any](s S)`:**

* **功能:**  反转切片 `s` 中元素的顺序。直接修改原始切片。
* **Go 语言功能:**  提供反转切片元素顺序的功能。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := []int{1, 2, 3, 4, 5}
	slices.Reverse(s)
	fmt.Println(s) // Output: [5 4 3 2 1]
}
```

**19. `Concat[S ~[]E, E any](slices ...S) S`:**

* **功能:**  将多个切片连接成一个新的切片并返回。
* **Go 语言功能:**  提供连接多个切片的功能。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s1 := []int{1, 2}
	s2 := []int{3, 4}
	s3 := slices.Concat(s1, s2)
	fmt.Println(s3) // Output: [1 2 3 4]
}
```

**20. `Repeat[S ~[]E, E any](x S, count int) S`:**

* **功能:**  创建一个新的切片，其中包含切片 `x` 重复 `count` 次的结果。
* **Go 语言功能:**  提供重复切片的功能。
* **代码示例:**

```go
package main

import (
	"fmt"
	"slices"
)

func main() {
	s := []int{1, 2}
	repeated := slices.Repeat(s, 3)
	fmt.Println(repeated) // Output: [1 2 1 2 1 2]
}
```

**命令行参数处理:**

这个文件中的函数主要用于对切片进行操作，并不涉及直接处理命令行参数。命令行参数的处理通常在 `main` 函数中使用 `os` 包的 `Args` 变量或者 `flag` 包来实现。

**使用者易犯错的点:**

* **`Equal` vs. `==`:** 容易忘记切片的 `==` 运算符比较的是引用，而不是内容。应该使用 `slices.Equal` 进行内容比较。
* **修改原始切片:**  像 `Compact` 和 `Reverse` 这样的函数会直接修改传入的切片。如果需要保留原始切片，应该先使用 `Clone` 创建一个副本。
* **切片的容量:**  在进行插入、删除等操作时，如果不理解切片的容量，可能会导致意外的内存分配和性能问题。使用 `Grow` 可以预先分配容量。
* **`Delete` 的索引范围:**  需要注意 `Delete` 函数的第二个参数 `j` 是**不包含**在删除范围内的。
* **浅拷贝:** `Clone` 函数执行的是浅拷贝。如果切片的元素是引用类型（例如指针、切片、map），则克隆后的切片与原始切片共享这些引用指向的数据。修改克隆切片中的引用类型元素会影响原始切片。

总而言之，`go/src/slices/slices.go` 提供了一组强大且常用的切片操作函数，极大地增强了 Go 语言处理切片的能力，使得开发者能够更方便、更高效地操作切片数据。

### 提示词
```
这是路径为go/src/slices/slices.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
请用中文回答。
```

### 源代码
```go
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package slices defines various functions useful with slices of any type.
package slices

import (
	"cmp"
	"math/bits"
	"unsafe"
)

// Equal reports whether two slices are equal: the same length and all
// elements equal. If the lengths are different, Equal returns false.
// Otherwise, the elements are compared in increasing index order, and the
// comparison stops at the first unequal pair.
// Empty and nil slices are considered equal.
// Floating point NaNs are not considered equal.
func Equal[S ~[]E, E comparable](s1, s2 S) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}

// EqualFunc reports whether two slices are equal using an equality
// function on each pair of elements. If the lengths are different,
// EqualFunc returns false. Otherwise, the elements are compared in
// increasing index order, and the comparison stops at the first index
// for which eq returns false.
func EqualFunc[S1 ~[]E1, S2 ~[]E2, E1, E2 any](s1 S1, s2 S2, eq func(E1, E2) bool) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i, v1 := range s1 {
		v2 := s2[i]
		if !eq(v1, v2) {
			return false
		}
	}
	return true
}

// Compare compares the elements of s1 and s2, using [cmp.Compare] on each pair
// of elements. The elements are compared sequentially, starting at index 0,
// until one element is not equal to the other.
// The result of comparing the first non-matching elements is returned.
// If both slices are equal until one of them ends, the shorter slice is
// considered less than the longer one.
// The result is 0 if s1 == s2, -1 if s1 < s2, and +1 if s1 > s2.
func Compare[S ~[]E, E cmp.Ordered](s1, s2 S) int {
	for i, v1 := range s1 {
		if i >= len(s2) {
			return +1
		}
		v2 := s2[i]
		if c := cmp.Compare(v1, v2); c != 0 {
			return c
		}
	}
	if len(s1) < len(s2) {
		return -1
	}
	return 0
}

// CompareFunc is like [Compare] but uses a custom comparison function on each
// pair of elements.
// The result is the first non-zero result of cmp; if cmp always
// returns 0 the result is 0 if len(s1) == len(s2), -1 if len(s1) < len(s2),
// and +1 if len(s1) > len(s2).
func CompareFunc[S1 ~[]E1, S2 ~[]E2, E1, E2 any](s1 S1, s2 S2, cmp func(E1, E2) int) int {
	for i, v1 := range s1 {
		if i >= len(s2) {
			return +1
		}
		v2 := s2[i]
		if c := cmp(v1, v2); c != 0 {
			return c
		}
	}
	if len(s1) < len(s2) {
		return -1
	}
	return 0
}

// Index returns the index of the first occurrence of v in s,
// or -1 if not present.
func Index[S ~[]E, E comparable](s S, v E) int {
	for i := range s {
		if v == s[i] {
			return i
		}
	}
	return -1
}

// IndexFunc returns the first index i satisfying f(s[i]),
// or -1 if none do.
func IndexFunc[S ~[]E, E any](s S, f func(E) bool) int {
	for i := range s {
		if f(s[i]) {
			return i
		}
	}
	return -1
}

// Contains reports whether v is present in s.
func Contains[S ~[]E, E comparable](s S, v E) bool {
	return Index(s, v) >= 0
}

// ContainsFunc reports whether at least one
// element e of s satisfies f(e).
func ContainsFunc[S ~[]E, E any](s S, f func(E) bool) bool {
	return IndexFunc(s, f) >= 0
}

// Insert inserts the values v... into s at index i,
// returning the modified slice.
// The elements at s[i:] are shifted up to make room.
// In the returned slice r, r[i] == v[0],
// and, if i < len(s), r[i+len(v)] == value originally at r[i].
// Insert panics if i > len(s).
// This function is O(len(s) + len(v)).
func Insert[S ~[]E, E any](s S, i int, v ...E) S {
	_ = s[i:] // bounds check

	m := len(v)
	if m == 0 {
		return s
	}
	n := len(s)
	if i == n {
		return append(s, v...)
	}
	if n+m > cap(s) {
		// Use append rather than make so that we bump the size of
		// the slice up to the next storage class.
		// This is what Grow does but we don't call Grow because
		// that might copy the values twice.
		s2 := append(s[:i], make(S, n+m-i)...)
		copy(s2[i:], v)
		copy(s2[i+m:], s[i:])
		return s2
	}
	s = s[:n+m]

	// before:
	// s: aaaaaaaabbbbccccccccdddd
	//            ^   ^       ^   ^
	//            i  i+m      n  n+m
	// after:
	// s: aaaaaaaavvvvbbbbcccccccc
	//            ^   ^       ^   ^
	//            i  i+m      n  n+m
	//
	// a are the values that don't move in s.
	// v are the values copied in from v.
	// b and c are the values from s that are shifted up in index.
	// d are the values that get overwritten, never to be seen again.

	if !overlaps(v, s[i+m:]) {
		// Easy case - v does not overlap either the c or d regions.
		// (It might be in some of a or b, or elsewhere entirely.)
		// The data we copy up doesn't write to v at all, so just do it.

		copy(s[i+m:], s[i:])

		// Now we have
		// s: aaaaaaaabbbbbbbbcccccccc
		//            ^   ^       ^   ^
		//            i  i+m      n  n+m
		// Note the b values are duplicated.

		copy(s[i:], v)

		// Now we have
		// s: aaaaaaaavvvvbbbbcccccccc
		//            ^   ^       ^   ^
		//            i  i+m      n  n+m
		// That's the result we want.
		return s
	}

	// The hard case - v overlaps c or d. We can't just shift up
	// the data because we'd move or clobber the values we're trying
	// to insert.
	// So instead, write v on top of d, then rotate.
	copy(s[n:], v)

	// Now we have
	// s: aaaaaaaabbbbccccccccvvvv
	//            ^   ^       ^   ^
	//            i  i+m      n  n+m

	rotateRight(s[i:], m)

	// Now we have
	// s: aaaaaaaavvvvbbbbcccccccc
	//            ^   ^       ^   ^
	//            i  i+m      n  n+m
	// That's the result we want.
	return s
}

// Delete removes the elements s[i:j] from s, returning the modified slice.
// Delete panics if j > len(s) or s[i:j] is not a valid slice of s.
// Delete is O(len(s)-i), so if many items must be deleted, it is better to
// make a single call deleting them all together than to delete one at a time.
// Delete zeroes the elements s[len(s)-(j-i):len(s)].
func Delete[S ~[]E, E any](s S, i, j int) S {
	_ = s[i:j:len(s)] // bounds check

	if i == j {
		return s
	}

	oldlen := len(s)
	s = append(s[:i], s[j:]...)
	clear(s[len(s):oldlen]) // zero/nil out the obsolete elements, for GC
	return s
}

// DeleteFunc removes any elements from s for which del returns true,
// returning the modified slice.
// DeleteFunc zeroes the elements between the new length and the original length.
func DeleteFunc[S ~[]E, E any](s S, del func(E) bool) S {
	i := IndexFunc(s, del)
	if i == -1 {
		return s
	}
	// Don't start copying elements until we find one to delete.
	for j := i + 1; j < len(s); j++ {
		if v := s[j]; !del(v) {
			s[i] = v
			i++
		}
	}
	clear(s[i:]) // zero/nil out the obsolete elements, for GC
	return s[:i]
}

// Replace replaces the elements s[i:j] by the given v, and returns the
// modified slice.
// Replace panics if j > len(s) or s[i:j] is not a valid slice of s.
// When len(v) < (j-i), Replace zeroes the elements between the new length and the original length.
func Replace[S ~[]E, E any](s S, i, j int, v ...E) S {
	_ = s[i:j] // bounds check

	if i == j {
		return Insert(s, i, v...)
	}
	if j == len(s) {
		s2 := append(s[:i], v...)
		if len(s2) < len(s) {
			clear(s[len(s2):]) // zero/nil out the obsolete elements, for GC
		}
		return s2
	}

	tot := len(s[:i]) + len(v) + len(s[j:])
	if tot > cap(s) {
		// Too big to fit, allocate and copy over.
		s2 := append(s[:i], make(S, tot-i)...) // See Insert
		copy(s2[i:], v)
		copy(s2[i+len(v):], s[j:])
		return s2
	}

	r := s[:tot]

	if i+len(v) <= j {
		// Easy, as v fits in the deleted portion.
		copy(r[i:], v)
		copy(r[i+len(v):], s[j:])
		clear(s[tot:]) // zero/nil out the obsolete elements, for GC
		return r
	}

	// We are expanding (v is bigger than j-i).
	// The situation is something like this:
	// (example has i=4,j=8,len(s)=16,len(v)=6)
	// s: aaaaxxxxbbbbbbbbyy
	//        ^   ^       ^ ^
	//        i   j  len(s) tot
	// a: prefix of s
	// x: deleted range
	// b: more of s
	// y: area to expand into

	if !overlaps(r[i+len(v):], v) {
		// Easy, as v is not clobbered by the first copy.
		copy(r[i+len(v):], s[j:])
		copy(r[i:], v)
		return r
	}

	// This is a situation where we don't have a single place to which
	// we can copy v. Parts of it need to go to two different places.
	// We want to copy the prefix of v into y and the suffix into x, then
	// rotate |y| spots to the right.
	//
	//        v[2:]      v[:2]
	//         |           |
	// s: aaaavvvvbbbbbbbbvv
	//        ^   ^       ^ ^
	//        i   j  len(s) tot
	//
	// If either of those two destinations don't alias v, then we're good.
	y := len(v) - (j - i) // length of y portion

	if !overlaps(r[i:j], v) {
		copy(r[i:j], v[y:])
		copy(r[len(s):], v[:y])
		rotateRight(r[i:], y)
		return r
	}
	if !overlaps(r[len(s):], v) {
		copy(r[len(s):], v[:y])
		copy(r[i:j], v[y:])
		rotateRight(r[i:], y)
		return r
	}

	// Now we know that v overlaps both x and y.
	// That means that the entirety of b is *inside* v.
	// So we don't need to preserve b at all; instead we
	// can copy v first, then copy the b part of v out of
	// v to the right destination.
	k := startIdx(v, s[j:])
	copy(r[i:], v)
	copy(r[i+len(v):], r[i+k:])
	return r
}

// Clone returns a copy of the slice.
// The elements are copied using assignment, so this is a shallow clone.
// The result may have additional unused capacity.
func Clone[S ~[]E, E any](s S) S {
	// Preserve nilness in case it matters.
	if s == nil {
		return nil
	}
	// Avoid s[:0:0] as it leads to unwanted liveness when cloning a
	// zero-length slice of a large array; see https://go.dev/issue/68488.
	return append(S{}, s...)
}

// Compact replaces consecutive runs of equal elements with a single copy.
// This is like the uniq command found on Unix.
// Compact modifies the contents of the slice s and returns the modified slice,
// which may have a smaller length.
// Compact zeroes the elements between the new length and the original length.
func Compact[S ~[]E, E comparable](s S) S {
	if len(s) < 2 {
		return s
	}
	for k := 1; k < len(s); k++ {
		if s[k] == s[k-1] {
			s2 := s[k:]
			for k2 := 1; k2 < len(s2); k2++ {
				if s2[k2] != s2[k2-1] {
					s[k] = s2[k2]
					k++
				}
			}

			clear(s[k:]) // zero/nil out the obsolete elements, for GC
			return s[:k]
		}
	}
	return s
}

// CompactFunc is like [Compact] but uses an equality function to compare elements.
// For runs of elements that compare equal, CompactFunc keeps the first one.
// CompactFunc zeroes the elements between the new length and the original length.
func CompactFunc[S ~[]E, E any](s S, eq func(E, E) bool) S {
	if len(s) < 2 {
		return s
	}
	for k := 1; k < len(s); k++ {
		if eq(s[k], s[k-1]) {
			s2 := s[k:]
			for k2 := 1; k2 < len(s2); k2++ {
				if !eq(s2[k2], s2[k2-1]) {
					s[k] = s2[k2]
					k++
				}
			}

			clear(s[k:]) // zero/nil out the obsolete elements, for GC
			return s[:k]
		}
	}
	return s
}

// Grow increases the slice's capacity, if necessary, to guarantee space for
// another n elements. After Grow(n), at least n elements can be appended
// to the slice without another allocation. If n is negative or too large to
// allocate the memory, Grow panics.
func Grow[S ~[]E, E any](s S, n int) S {
	if n < 0 {
		panic("cannot be negative")
	}
	if n -= cap(s) - len(s); n > 0 {
		// This expression allocates only once (see test).
		s = append(s[:cap(s)], make([]E, n)...)[:len(s)]
	}
	return s
}

// Clip removes unused capacity from the slice, returning s[:len(s):len(s)].
func Clip[S ~[]E, E any](s S) S {
	return s[:len(s):len(s)]
}

// TODO: There are other rotate algorithms.
// This algorithm has the desirable property that it moves each element at most twice.
// The follow-cycles algorithm can be 1-write but it is not very cache friendly.

// rotateLeft rotates s left by r spaces.
// s_final[i] = s_orig[i+r], wrapping around.
func rotateLeft[E any](s []E, r int) {
	Reverse(s[:r])
	Reverse(s[r:])
	Reverse(s)
}
func rotateRight[E any](s []E, r int) {
	rotateLeft(s, len(s)-r)
}

// overlaps reports whether the memory ranges a[:len(a)] and b[:len(b)] overlap.
func overlaps[E any](a, b []E) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	elemSize := unsafe.Sizeof(a[0])
	if elemSize == 0 {
		return false
	}
	// TODO: use a runtime/unsafe facility once one becomes available. See issue 12445.
	// Also see crypto/internal/fips140/alias/alias.go:AnyOverlap
	return uintptr(unsafe.Pointer(&a[0])) <= uintptr(unsafe.Pointer(&b[len(b)-1]))+(elemSize-1) &&
		uintptr(unsafe.Pointer(&b[0])) <= uintptr(unsafe.Pointer(&a[len(a)-1]))+(elemSize-1)
}

// startIdx returns the index in haystack where the needle starts.
// prerequisite: the needle must be aliased entirely inside the haystack.
func startIdx[E any](haystack, needle []E) int {
	p := &needle[0]
	for i := range haystack {
		if p == &haystack[i] {
			return i
		}
	}
	// TODO: what if the overlap is by a non-integral number of Es?
	panic("needle not found")
}

// Reverse reverses the elements of the slice in place.
func Reverse[S ~[]E, E any](s S) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

// Concat returns a new slice concatenating the passed in slices.
func Concat[S ~[]E, E any](slices ...S) S {
	size := 0
	for _, s := range slices {
		size += len(s)
		if size < 0 {
			panic("len out of range")
		}
	}
	// Use Grow, not make, to round up to the size class:
	// the extra space is otherwise unused and helps
	// callers that append a few elements to the result.
	newslice := Grow[S](nil, size)
	for _, s := range slices {
		newslice = append(newslice, s...)
	}
	return newslice
}

// Repeat returns a new slice that repeats the provided slice the given number of times.
// The result has length and capacity (len(x) * count).
// The result is never nil.
// Repeat panics if count is negative or if the result of (len(x) * count)
// overflows.
func Repeat[S ~[]E, E any](x S, count int) S {
	if count < 0 {
		panic("cannot be negative")
	}

	const maxInt = ^uint(0) >> 1
	hi, lo := bits.Mul(uint(len(x)), uint(count))
	if hi > 0 || lo > maxInt {
		panic("the result of (len(x) * count) overflows")
	}

	newslice := make(S, int(lo)) // lo = len(x) * count
	n := copy(newslice, x)
	for n < len(newslice) {
		n += copy(newslice[n:], newslice[:n])
	}
	return newslice
}
```