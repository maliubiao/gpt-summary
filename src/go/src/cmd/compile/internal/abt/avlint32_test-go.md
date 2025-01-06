Response:
Let's break down the thought process for analyzing this Go code snippet.

1. **Identify the Core Purpose:** The filename `avlint32_test.go` strongly suggests this is a testing file. The `_test.go` suffix is a standard Go convention. The `avlint32` part is less immediately obvious, but the `abt` package import gives a clue. Looking at the function names like `applicInsert`, `applicFind`, etc., reinforces the idea that it's testing some data structure's functionality.

2. **Examine Imports:**  The imports `fmt`, `strconv`, and `testing` are standard Go libraries for formatting, string conversion, and testing, respectively. This further confirms the testing nature of the file.

3. **Analyze Key Data Structures and Types:** The code frequently uses a type `T`. Without the definition of `T`, we need to infer its behavior from how it's used. It has methods like `Insert`, `Find`, `Delete`, `Min`, `Max`, `Glb`, `Lub`, `Iterator`, `Equiv`, `Copy`, `Size`, `IsEmpty`, and `wellFormed`. This strongly suggests `T` is a data structure that supports ordered elements. The presence of `Glb` (Greatest Lower Bound) and `Lub` (Least Upper Bound) points towards a sorted set or map-like structure. The suffix `32` in the filename likely indicates that the keys are `int32`.

4. **Deconstruct Individual Functions:**

   * **`makeTree`:**  This function takes a slice of `int32`, inserts them into a `T`, and performs consistency checks if `check` is true. The doubling of `d` hints at a possible testing strategy for related functions like `Glb` and `Lub`. The `history` slice suggests a way to track the tree's evolution.

   * **`applicInsert`, `applicFind`, `applicBounds`, `applicDeleteMin`, `applicDeleteMax`, `applicDelete`, `applicIterator`, `applicEquals`:** These functions all follow a similar pattern:
      * They call `makeTree` to create an instance of `T`.
      * They then perform specific operations (insert, find, bound checks, deletes, iteration, equality checks) on the tree.
      * They use `te.Errorf` to report errors if the actual behavior doesn't match the expected behavior.

   * **Helper Functions:** `stringer`, `equiv`, `first`, `second`, `alwaysNil`, `smaller`, `assert`, `tree`, `treePlus1` are utility functions used within the tests. `stringer` seems to wrap a string into an interface suitable for the `T` data. `equiv` likely compares the data stored in the `T`. The other helper functions appear to be for testing different behaviors of set operations.

   * **`Test...` Functions:** These are standard Go test functions. Each `Test...` function calls one of the `applic...` functions with different input slices of `int32`. This shows different scenarios being tested.

   * **`wellFormed` and `wellFormedSubtree`:** These functions are crucial for verifying the internal consistency of the `T` data structure. They check red-black tree invariants (height differences, node ordering, etc.).

   * **`DebugString`:** This is a helper function to print the tree structure, useful for debugging.

5. **Infer the Go Feature:** Based on the methods of `T` and the focus on ordered data, the most likely Go feature being implemented is a **Red-Black Tree**. Red-Black trees are a type of self-balancing binary search tree, commonly used for implementing sets and maps. The `wellFormed` function and the checks it performs strongly support this inference, as these checks are characteristic of red-black tree invariants.

6. **Construct Example Usage:**  Knowing it's likely a Red-Black tree, we can create a plausible example. The `Insert`, `Find`, and iteration functionalities are common to such trees. We need to make an assumption about how data is stored alongside the integer keys. The code uses `stringer`, suggesting the data is being converted to strings.

7. **Analyze Error-Prone Areas:**  Consider common pitfalls when using tree-like data structures:
   * **Incorrect Comparison:**  The `Equiv` function using a custom comparison (`equiv`) highlights the importance of correct element comparison.
   * **Modification During Iteration:** The `applicIterator` function implicitly tests the safety of iteration alongside modification (deletion). This is a classic error source.
   * **Off-by-One Errors:**  Boundary conditions (min/max values) are explicitly tested in `applicBounds`, suggesting this is a potential area for errors.

8. **Address Command-Line Arguments:**  The provided code doesn't directly handle command-line arguments. Testing files often rely on Go's built-in testing framework, which is invoked through commands like `go test`.

9. **Refine and Organize:**  Finally, organize the findings into a clear and structured answer, addressing each point of the prompt. Use code examples where appropriate and provide clear explanations.

This thought process emphasizes deduction based on naming conventions, function signatures, and common data structure patterns. Even without the exact definition of `T`, a good understanding of the code's purpose and the underlying data structure can be inferred.
这个Go语言实现的一部分，即 `go/src/cmd/compile/internal/abt/avlint32_test.go`， 主要功能是 **测试 `abt` 包中实现的某种基于 `int32` 键的抽象数据类型（很可能是一个平衡二叉搜索树，比如红黑树）的正确性**。

更具体地说，它包含了一系列的测试用例，用于验证该数据结构的以下核心功能：

1. **插入 (Insert):**  测试向数据结构中插入新的键值对是否能正确完成，并保持数据结构的性质（例如，对于平衡树，保持平衡）。
2. **查找 (Find):** 测试能否根据给定的键正确地查找到对应的值。
3. **边界查询 (Bounds):** 测试查找给定键的下界（Greatest Lower Bound, Glb）和上界（Least Upper Bound, Lub）的功能，包括相等的情况。
4. **删除最小值 (DeleteMin):** 测试删除数据结构中最小键值对的功能。
5. **删除最大值 (DeleteMax):** 测试删除数据结构中最大键值对的功能。
6. **删除指定键 (Delete):** 测试删除指定键的键值对的功能。
7. **迭代器 (Iterator):** 测试遍历数据结构中所有键值对的功能。
8. **相等性判断 (Equals/Equiv):** 测试判断两个数据结构是否包含相同的键值对的功能。
9. **集合操作 (SetOps):** 测试数据结构的集合操作，例如交集 (Intersection)，并集 (Union)，差集 (Difference)。

**推理：这是一个红黑树的实现**

基于以下几点，可以推断 `abt` 包实现的很可能是一个红黑树（或者其他自平衡的二叉搜索树）：

* **`wellFormed()` 方法：**  这个方法用于检查树的内部一致性，而 `wellFormedSubtree()` 方法中检查了节点的 `height_` 以及高度差 `dh` 是否超过 1。这些都是红黑树（或其他平衡树）的关键性质。
* **文件名中的 `avl` 暗示：** 虽然文件名是 `avlint32_test.go`，但 `abt` 包名更常用，`avl` 可能是最初的实现思路或者部分测试用例的遗留。红黑树和 AVL 树都是常见的自平衡二叉搜索树。
* **`Glb` 和 `Lub` 方法：** 这些方法在有序数据结构中很常见，特别是在需要查找范围或近似匹配时。
* **频繁的 `Copy()` 操作和一致性检查：** 测试代码中在每次插入和删除后都会进行一致性检查，这对于保证复杂数据结构的正确性至关重要。

**Go 代码举例说明 (假设 `T` 是一个红黑树的实现):**

假设 `abt` 包中定义了一个名为 `T` 的类型，表示一个键为 `int32`，值为 `interface{}` 的红黑树。

```go
package abt

import "fmt"

// 假设这是 abt 包中 T 类型的定义
type T struct {
	root *node32
	// ... 其他字段
}

type node32 struct {
	key    int32
	data   interface{}
	left   *node32
	right  *node32
	height_ int8
	// ... 其他字段 (例如 color)
}

// Insert 向树中插入一个键值对
func (t *T) Insert(key int32, data interface{}) {
	// ... 红黑树插入的实现
}

// Find 根据键查找对应的值
func (t *T) Find(key int32) interface{} {
	// ... 红黑树查找的实现
	return nil // 示例，实际需要返回找到的值
}

// ... 其他方法 (Delete, Min, Max, Glb, Lub, Iterator, Equiv, Copy, Size, IsEmpty, wellFormed) 的定义
```

**测试用例示例：**

```go
package abt_test

import (
	"fmt"
	"testing"
	"go/src/cmd/compile/internal/abt" // 假设 abt 包的路径
)

func TestRedBlackTreeInsertFind(t *testing.T) {
	tree := &abt.T{}

	// 插入一些数据
	tree.Insert(10, "value10")
	tree.Insert(5, "value5")
	tree.Insert(15, "value15")

	// 查找数据
	val := tree.Find(10)
	if val != "value10" {
		t.Errorf("Expected value10 for key 10, got %v", val)
	}

	val = tree.Find(5)
	if val != "value5" {
		t.Errorf("Expected value5 for key 5, got %v", val)
	}

	val = tree.Find(20) // 查找不存在的键
	if val != nil {
		t.Errorf("Expected nil for key 20, got %v", val)
	}
}
```

**假设的输入与输出 (基于 `applicInsert` 函数):**

假设 `applicInsert` 函数被调用，输入是 `x := []int32{3, 1, 4, 2}`。

1. **第一次迭代 (d = 3 * 2 = 6):**
   - 插入键 `6`，值为字符串 `"6"`。
   - 树的状态可能类似于： `[6:6]` (键:值)

2. **第二次迭代 (d = 1 * 2 = 2):**
   - 插入键 `2`，值为字符串 `"2"`。
   - 树的状态可能类似于：
     ```
         6:6
        /
       2:2
     ```

3. **第三次迭代 (d = 4 * 2 = 8):**
   - 插入键 `8`，值为字符串 `"8"`。
   - 树的状态可能类似于：
     ```
         6:6
        / \
       2:2 8:8
     ```

4. **第四次迭代 (d = 2 * 2 = 4):**
   - 插入键 `4`，值为字符串 `"4"`。
   - 树的状态可能需要重新平衡，最终可能类似于：
     ```
         4:4
        / \
       2:2 6:6
            \
             8:8
     ```

在每次插入后，`makeTree` 函数会调用 `t.wellFormed()` 来检查树是否仍然满足红黑树的性质。如果检查失败，测试会报错。

**命令行参数的具体处理：**

这个代码片段本身不直接处理命令行参数。它是 Go 语言的测试代码，通常通过 Go 的内置测试工具 `go test` 来运行。

当你运行 `go test` 命令时，Go 工具会：

1. 查找当前目录及其子目录中所有以 `_test.go` 结尾的文件。
2. 编译这些测试文件。
3. 运行其中所有以 `Test` 开头的函数。

你可以使用 `go test` 的一些命令行参数来控制测试的运行方式，例如：

* **`-v` (verbose):**  显示所有测试用例的运行结果，包括成功的用例。
* **`-run <regexp>`:**  只运行名称匹配指定正则表达式的测试用例。例如，`go test -run Insert` 只会运行名字包含 "Insert" 的测试用例。
* **`-bench <regexp>`:** 运行性能测试 (benchmark)。虽然这个文件中没有 benchmark，但了解一下也很重要。
* **`-coverprofile <file>`:**  生成代码覆盖率报告。

例如，要运行 `avlint32_test.go` 中的所有测试用例，你需要在 `go/src/cmd/compile/internal/abt/` 目录下执行：

```bash
go test
```

或者，要运行特定的测试用例，例如 `TestApplicInsert`，可以执行：

```bash
go test -run ApplicInsert
```

**使用者易犯错的点 (基于代码推理):**

1. **假设值的类型：**  `T` 结构存储的值是 `interface{}` 类型的。使用者在获取值后可能需要进行类型断言，如果断言的类型不正确，会导致运行时错误。
   ```go
   val := tree.Find(10)
   strVal, ok := val.(*sstring) // 假设值被包装在 *sstring 中
   if !ok {
       // 类型断言失败
       fmt.Println("Unexpected value type")
   } else {
       fmt.Println("Value:", strVal.s)
   }
   ```

2. **使用 `Equiv` 函数进行比较时，提供的比较函数不正确：** `Equiv` 函数接受一个比较函数作为参数。如果提供的比较函数不能正确地判断两个节点的值是否相等，会导致错误的比较结果。例如，如果只是简单地比较指针地址，而不是比较实际的值内容。

3. **在迭代过程中修改树结构：**  虽然代码中 `applicIterator` 看起来是在迭代过程中删除元素，但这种操作需要谨慎处理。如果迭代器的实现没有考虑到并发修改，可能会导致迭代过程中的数据不一致或者程序崩溃。在这个特定的测试用例中，迭代器似乎与 `DeleteMin` 配套使用，保证了按顺序删除，但这并不是通用的安全做法。

4. **对 `Glb` 和 `Lub` 的理解偏差：**  使用者可能不清楚 `Glb` 返回小于或等于给定键的最大键，而 `Lub` 返回大于或等于给定键的最小键。如果理解有误，可能会导致使用 `Glb` 和 `Lub` 时得到意外的结果。

总而言之，`go/src/cmd/compile/internal/abt/avlint32_test.go` 是一个全面的测试文件，用于验证 `abt` 包中实现的基于 `int32` 键的抽象数据类型的正确性和鲁棒性，很可能是对一个红黑树的实现进行测试。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/abt/avlint32_test.go的go语言实现的一部分， 请列举一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果涉及代码推理，需要带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，

"""
// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package abt

import (
	"fmt"
	"strconv"
	"testing"
)

func makeTree(te *testing.T, x []int32, check bool) (t *T, k int, min, max int32) {
	t = &T{}
	k = 0
	min = int32(0x7fffffff)
	max = int32(-0x80000000)
	history := []*T{}

	for _, d := range x {
		d = d + d // double everything for Glb/Lub testing.

		if check {
			history = append(history, t.Copy())
		}

		t.Insert(d, stringer(fmt.Sprintf("%v", d)))

		k++
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}

		if !check {
			continue
		}

		for j, old := range history {
			s, i := old.wellFormed()
			if s != "" {
				te.Errorf("Old tree consistency problem %v at k=%d, j=%d, old=\n%v, t=\n%v", s, k, j, old.DebugString(), t.DebugString())
				return
			}
			if i != j {
				te.Errorf("Wrong tree size %v, expected %v for old %v", i, j, old.DebugString())
			}
		}
		s, i := t.wellFormed()
		if s != "" {
			te.Errorf("Tree consistency problem at %v", s)
			return
		}
		if i != k {
			te.Errorf("Wrong tree size %v, expected %v for %v", i, k, t.DebugString())
			return
		}
		if t.Size() != k {
			te.Errorf("Wrong t.Size() %v, expected %v for %v", t.Size(), k, t.DebugString())
			return
		}
	}
	return
}

func applicInsert(te *testing.T, x []int32) {
	makeTree(te, x, true)
}

func applicFind(te *testing.T, x []int32) {
	t, _, _, _ := makeTree(te, x, false)

	for _, d := range x {
		d = d + d // double everything for Glb/Lub testing.
		s := fmt.Sprintf("%v", d)
		f := t.Find(d)

		// data
		if s != fmt.Sprint(f) {
			te.Errorf("s(%v) != f(%v)", s, f)
		}
	}
}

func applicBounds(te *testing.T, x []int32) {
	t, _, min, max := makeTree(te, x, false)
	for _, d := range x {
		d = d + d // double everything for Glb/Lub testing.
		s := fmt.Sprintf("%v", d)

		kg, g := t.Glb(d + 1)
		kge, ge := t.GlbEq(d)
		kl, l := t.Lub(d - 1)
		kle, le := t.LubEq(d)

		// keys
		if d != kg {
			te.Errorf("d(%v) != kg(%v)", d, kg)
		}
		if d != kl {
			te.Errorf("d(%v) != kl(%v)", d, kl)
		}
		if d != kge {
			te.Errorf("d(%v) != kge(%v)", d, kge)
		}
		if d != kle {
			te.Errorf("d(%v) != kle(%v)", d, kle)
		}
		// data
		if s != fmt.Sprint(g) {
			te.Errorf("s(%v) != g(%v)", s, g)
		}
		if s != fmt.Sprint(l) {
			te.Errorf("s(%v) != l(%v)", s, l)
		}
		if s != fmt.Sprint(ge) {
			te.Errorf("s(%v) != ge(%v)", s, ge)
		}
		if s != fmt.Sprint(le) {
			te.Errorf("s(%v) != le(%v)", s, le)
		}
	}

	for _, d := range x {
		d = d + d // double everything for Glb/Lub testing.
		s := fmt.Sprintf("%v", d)
		kge, ge := t.GlbEq(d + 1)
		kle, le := t.LubEq(d - 1)
		if d != kge {
			te.Errorf("d(%v) != kge(%v)", d, kge)
		}
		if d != kle {
			te.Errorf("d(%v) != kle(%v)", d, kle)
		}
		if s != fmt.Sprint(ge) {
			te.Errorf("s(%v) != ge(%v)", s, ge)
		}
		if s != fmt.Sprint(le) {
			te.Errorf("s(%v) != le(%v)", s, le)
		}
	}

	kg, g := t.Glb(min)
	kge, ge := t.GlbEq(min - 1)
	kl, l := t.Lub(max)
	kle, le := t.LubEq(max + 1)
	fmin := t.Find(min - 1)
	fmax := t.Find(max + 1)

	if kg != NOT_KEY32 || kge != NOT_KEY32 || kl != NOT_KEY32 || kle != NOT_KEY32 {
		te.Errorf("Got non-error-key for missing query")
	}

	if g != nil || ge != nil || l != nil || le != nil || fmin != nil || fmax != nil {
		te.Errorf("Got non-error-data for missing query")
	}
}

func applicDeleteMin(te *testing.T, x []int32) {
	t, _, _, _ := makeTree(te, x, false)
	_, size := t.wellFormed()
	history := []*T{}
	for !t.IsEmpty() {
		k, _ := t.Min()
		history = append(history, t.Copy())
		kd, _ := t.DeleteMin()
		if kd != k {
			te.Errorf("Deleted minimum key %v not equal to minimum %v", kd, k)
		}
		for j, old := range history {
			s, i := old.wellFormed()
			if s != "" {
				te.Errorf("Tree consistency problem %s at old after DeleteMin, old=\n%stree=\n%v", s, old.DebugString(), t.DebugString())
				return
			}
			if i != len(x)-j {
				te.Errorf("Wrong old tree size %v, expected %v after DeleteMin, old=\n%vtree\n%v", i, len(x)-j, old.DebugString(), t.DebugString())
				return
			}
		}
		size--
		s, i := t.wellFormed()
		if s != "" {
			te.Errorf("Tree consistency problem at %v after DeleteMin, tree=\n%v", s, t.DebugString())
			return
		}
		if i != size {
			te.Errorf("Wrong tree size %v, expected %v after DeleteMin", i, size)
			return
		}
		if t.Size() != size {
			te.Errorf("Wrong t.Size() %v, expected %v for %v", t.Size(), i, t.DebugString())
			return
		}
	}
}

func applicDeleteMax(te *testing.T, x []int32) {
	t, _, _, _ := makeTree(te, x, false)
	_, size := t.wellFormed()
	history := []*T{}

	for !t.IsEmpty() {
		k, _ := t.Max()
		history = append(history, t.Copy())
		kd, _ := t.DeleteMax()
		if kd != k {
			te.Errorf("Deleted maximum key %v not equal to maximum %v", kd, k)
		}

		for j, old := range history {
			s, i := old.wellFormed()
			if s != "" {
				te.Errorf("Tree consistency problem %s at old after DeleteMin, old=\n%stree=\n%v", s, old.DebugString(), t.DebugString())
				return
			}
			if i != len(x)-j {
				te.Errorf("Wrong old tree size %v, expected %v after DeleteMin, old=\n%vtree\n%v", i, len(x)-j, old.DebugString(), t.DebugString())
				return
			}
		}

		size--
		s, i := t.wellFormed()
		if s != "" {
			te.Errorf("Tree consistency problem at %v after DeleteMax, tree=\n%v", s, t.DebugString())
			return
		}
		if i != size {
			te.Errorf("Wrong tree size %v, expected %v after DeleteMax", i, size)
			return
		}
		if t.Size() != size {
			te.Errorf("Wrong t.Size() %v, expected %v for %v", t.Size(), i, t.DebugString())
			return
		}
	}
}

func applicDelete(te *testing.T, x []int32) {
	t, _, _, _ := makeTree(te, x, false)
	_, size := t.wellFormed()
	history := []*T{}

	missing := t.Delete(11)
	if missing != nil {
		te.Errorf("Returned a value when there should have been none, %v", missing)
		return
	}

	s, i := t.wellFormed()
	if s != "" {
		te.Errorf("Tree consistency problem at %v after delete of missing value, tree=\n%v", s, t.DebugString())
		return
	}
	if size != i {
		te.Errorf("Delete of missing data should not change tree size, expected %d, got %d", size, i)
		return
	}

	for _, d := range x {
		d += d // double
		vWant := fmt.Sprintf("%v", d)
		history = append(history, t.Copy())
		v := t.Delete(d)

		for j, old := range history {
			s, i := old.wellFormed()
			if s != "" {
				te.Errorf("Tree consistency problem %s at old after DeleteMin, old=\n%stree=\n%v", s, old.DebugString(), t.DebugString())
				return
			}
			if i != len(x)-j {
				te.Errorf("Wrong old tree size %v, expected %v after DeleteMin, old=\n%vtree\n%v", i, len(x)-j, old.DebugString(), t.DebugString())
				return
			}
		}

		if v.(*sstring).s != vWant {
			te.Errorf("Deleted %v expected %v but got %v", d, vWant, v)
			return
		}
		size--
		s, i := t.wellFormed()
		if s != "" {
			te.Errorf("Tree consistency problem at %v after Delete %d, tree=\n%v", s, d, t.DebugString())
			return
		}
		if i != size {
			te.Errorf("Wrong tree size %v, expected %v after Delete", i, size)
			return
		}
		if t.Size() != size {
			te.Errorf("Wrong t.Size() %v, expected %v for %v", t.Size(), i, t.DebugString())
			return
		}
	}

}

func applicIterator(te *testing.T, x []int32) {
	t, _, _, _ := makeTree(te, x, false)
	it := t.Iterator()
	for !it.Done() {
		k0, d0 := it.Next()
		k1, d1 := t.DeleteMin()
		if k0 != k1 || d0 != d1 {
			te.Errorf("Iterator and deleteMin mismatch, k0, k1, d0, d1 = %v, %v, %v, %v", k0, k1, d0, d1)
			return
		}
	}
	if t.Size() != 0 {
		te.Errorf("Iterator ended early, remaining tree = \n%s", t.DebugString())
		return
	}
}

func equiv(a, b interface{}) bool {
	sa, sb := a.(*sstring), b.(*sstring)
	return *sa == *sb
}

func applicEquals(te *testing.T, x, y []int32) {
	t, _, _, _ := makeTree(te, x, false)
	u, _, _, _ := makeTree(te, y, false)
	if !t.Equiv(t, equiv) {
		te.Errorf("Equiv failure, t == t, =\n%v", t.DebugString())
		return
	}
	if !t.Equiv(t.Copy(), equiv) {
		te.Errorf("Equiv failure, t == t.Copy(), =\n%v", t.DebugString())
		return
	}
	if !t.Equiv(u, equiv) {
		te.Errorf("Equiv failure, t == u, =\n%v", t.DebugString())
		return
	}
	v := t.Copy()

	v.DeleteMax()
	if t.Equiv(v, equiv) {
		te.Errorf("!Equiv failure, t != v, =\n%v\nand%v\n", t.DebugString(), v.DebugString())
		return
	}

	if v.Equiv(u, equiv) {
		te.Errorf("!Equiv failure, v != u, =\n%v\nand%v\n", v.DebugString(), u.DebugString())
		return
	}

}

func tree(x []int32) *T {
	t := &T{}
	for _, d := range x {
		t.Insert(d, stringer(fmt.Sprintf("%v", d)))
	}
	return t
}

func treePlus1(x []int32) *T {
	t := &T{}
	for _, d := range x {
		t.Insert(d, stringer(fmt.Sprintf("%v", d+1)))
	}
	return t
}
func TestApplicInsert(t *testing.T) {
	applicInsert(t, []int32{24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25})
	applicInsert(t, []int32{1, 2, 3, 4})
	applicInsert(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9})
	applicInsert(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25})
	applicInsert(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicInsert(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicInsert(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24})
	applicInsert(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2})
}

func TestApplicFind(t *testing.T) {
	applicFind(t, []int32{24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25})
	applicFind(t, []int32{1, 2, 3, 4})
	applicFind(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9})
	applicFind(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25})
	applicFind(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicFind(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicFind(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24})
	applicFind(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2})
}

func TestBounds(t *testing.T) {
	applicBounds(t, []int32{24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25})
	applicBounds(t, []int32{1, 2, 3, 4})
	applicBounds(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9})
	applicBounds(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25})
	applicBounds(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicBounds(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicBounds(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24})
	applicBounds(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2})
}
func TestDeleteMin(t *testing.T) {
	applicDeleteMin(t, []int32{1, 2, 3, 4})
	applicDeleteMin(t, []int32{24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25})
	applicDeleteMin(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9})
	applicDeleteMin(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25})
	applicDeleteMin(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicDeleteMin(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicDeleteMin(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24})
	applicDeleteMin(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2})
}
func TestDeleteMax(t *testing.T) {
	applicDeleteMax(t, []int32{24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25})
	applicDeleteMax(t, []int32{1, 2, 3, 4})
	applicDeleteMax(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9})
	applicDeleteMax(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25})
	applicDeleteMax(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicDeleteMax(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicDeleteMax(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24})
	applicDeleteMax(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2})
}
func TestDelete(t *testing.T) {
	applicDelete(t, []int32{24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25})
	applicDelete(t, []int32{1, 2, 3, 4})
	applicDelete(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9})
	applicDelete(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25})
	applicDelete(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicDelete(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicDelete(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24})
	applicDelete(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2})
}
func TestIterator(t *testing.T) {
	applicIterator(t, []int32{1, 2, 3, 4})
	applicIterator(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9})
	applicIterator(t, []int32{24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25})
	applicIterator(t, []int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25})
	applicIterator(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicIterator(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicIterator(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24})
	applicIterator(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2})
}
func TestEquals(t *testing.T) {
	applicEquals(t, []int32{1, 2, 3, 4}, []int32{4, 3, 2, 1})

	applicEquals(t, []int32{24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25},
		[]int32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25})
	applicEquals(t, []int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
		[]int32{25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1})
	applicEquals(t, []int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24},
		[]int32{1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 24, 22, 20, 18, 16, 14, 12, 10, 8, 6, 4, 2})
}

func first(x, y interface{}) interface{} {
	return x
}
func second(x, y interface{}) interface{} {
	return y
}
func alwaysNil(x, y interface{}) interface{} {
	return nil
}
func smaller(x, y interface{}) interface{} {
	xi, _ := strconv.Atoi(fmt.Sprint(x))
	yi, _ := strconv.Atoi(fmt.Sprint(y))
	if xi < yi {
		return x
	}
	return y
}
func assert(t *testing.T, expected, got *T, what string) {
	s, _ := got.wellFormed()
	if s != "" {
		t.Errorf("Tree consistency problem %v for 'got' in assert for %s, tree=\n%v", s, what, got.DebugString())
		return
	}

	if !expected.Equiv(got, equiv) {
		t.Errorf("%s fail, expected\n%vgot\n%v\n", what, expected.DebugString(), got.DebugString())
	}
}

func TestSetOps(t *testing.T) {
	A := tree([]int32{1, 2, 3, 4})
	B := tree([]int32{3, 4, 5, 6, 7})

	AIB := tree([]int32{3, 4})
	ADB := tree([]int32{1, 2})
	BDA := tree([]int32{5, 6, 7})
	AUB := tree([]int32{1, 2, 3, 4, 5, 6, 7})
	AXB := tree([]int32{1, 2, 5, 6, 7})

	aib1 := A.Intersection(B, first)
	assert(t, AIB, aib1, "aib1")
	if A.Find(3) != aib1.Find(3) {
		t.Errorf("Failed aliasing/reuse check, A/aib1")
	}
	aib2 := A.Intersection(B, second)
	assert(t, AIB, aib2, "aib2")
	if B.Find(3) != aib2.Find(3) {
		t.Errorf("Failed aliasing/reuse check, B/aib2")
	}
	aib3 := B.Intersection(A, first)
	assert(t, AIB, aib3, "aib3")
	if A.Find(3) != aib3.Find(3) {
		// A is smaller, intersection favors reuse from smaller when function is "first"
		t.Errorf("Failed aliasing/reuse check, A/aib3")
	}
	aib4 := B.Intersection(A, second)
	assert(t, AIB, aib4, "aib4")
	if A.Find(3) != aib4.Find(3) {
		t.Errorf("Failed aliasing/reuse check, A/aib4")
	}

	aub1 := A.Union(B, first)
	assert(t, AUB, aub1, "aub1")
	if B.Find(3) != aub1.Find(3) {
		// B is larger, union favors reuse from larger when function is "first"
		t.Errorf("Failed aliasing/reuse check, A/aub1")
	}
	aub2 := A.Union(B, second)
	assert(t, AUB, aub2, "aub2")
	if B.Find(3) != aub2.Find(3) {
		t.Errorf("Failed aliasing/reuse check, B/aub2")
	}
	aub3 := B.Union(A, first)
	assert(t, AUB, aub3, "aub3")
	if B.Find(3) != aub3.Find(3) {
		t.Errorf("Failed aliasing/reuse check, B/aub3")
	}
	aub4 := B.Union(A, second)
	assert(t, AUB, aub4, "aub4")
	if A.Find(3) != aub4.Find(3) {
		t.Errorf("Failed aliasing/reuse check, A/aub4")
	}

	axb1 := A.Union(B, alwaysNil)
	assert(t, AXB, axb1, "axb1")
	axb2 := B.Union(A, alwaysNil)
	assert(t, AXB, axb2, "axb2")

	adb := A.Difference(B, alwaysNil)
	assert(t, ADB, adb, "adb")
	bda := B.Difference(A, nil)
	assert(t, BDA, bda, "bda")

	Ap1 := treePlus1([]int32{1, 2, 3, 4})

	ada1_1 := A.Difference(Ap1, smaller)
	assert(t, A, ada1_1, "ada1_1")
	ada1_2 := Ap1.Difference(A, smaller)
	assert(t, A, ada1_2, "ada1_2")

}

type sstring struct {
	s string
}

func (s *sstring) String() string {
	return s.s
}

func stringer(s string) interface{} {
	return &sstring{s}
}

// wellFormed ensures that a red-black tree meets
// all of its invariants and returns a string identifying
// the first problem encountered. If there is no problem
// then the returned string is empty. The size is also
// returned to allow comparison of calculated tree size
// with expected.
func (t *T) wellFormed() (s string, i int) {
	if t.root == nil {
		s = ""
		i = 0
		return
	}
	return t.root.wellFormedSubtree(nil, -0x80000000, 0x7fffffff)
}

// wellFormedSubtree ensures that a red-black subtree meets
// all of its invariants and returns a string identifying
// the first problem encountered. If there is no problem
// then the returned string is empty. The size is also
// returned to allow comparison of calculated tree size
// with expected.
func (t *node32) wellFormedSubtree(parent *node32, keyMin, keyMax int32) (s string, i int) {
	i = -1 // initialize to a failing value
	s = "" // s is the reason for failure; empty means okay.

	if keyMin >= t.key {
		s = " min >= t.key"
		return
	}

	if keyMax <= t.key {
		s = " max <= t.key"
		return
	}

	l := t.left
	r := t.right

	lh := l.height()
	rh := r.height()
	mh := max(lh, rh)
	th := t.height()
	dh := lh - rh
	if dh < 0 {
		dh = -dh
	}
	if dh > 1 {
		s = fmt.Sprintf(" dh > 1, t=%d", t.key)
		return
	}

	if l == nil && r == nil {
		if th != LEAF_HEIGHT {
			s = " leaf height wrong"
			return
		}
	}

	if th != mh+1 {
		s = " th != mh + 1"
		return
	}

	if l != nil {
		if th <= lh {
			s = " t.height <= l.height"
		} else if th > 2+lh {
			s = " t.height > 2+l.height"
		} else if t.key <= l.key {
			s = " t.key <= l.key"
		}
		if s != "" {
			return
		}

	}

	if r != nil {
		if th <= rh {
			s = " t.height <= r.height"
		} else if th > 2+rh {
			s = " t.height > 2+r.height"
		} else if t.key >= r.key {
			s = " t.key >= r.key"
		}
		if s != "" {
			return
		}
	}

	ii := 1
	if l != nil {
		res, il := l.wellFormedSubtree(t, keyMin, t.key)
		if res != "" {
			s = ".L" + res
			return
		}
		ii += il
	}
	if r != nil {
		res, ir := r.wellFormedSubtree(t, t.key, keyMax)
		if res != "" {
			s = ".R" + res
			return
		}
		ii += ir
	}
	i = ii
	return
}

func (t *T) DebugString() string {
	if t.root == nil {
		return ""
	}
	return t.root.DebugString(0)
}

// DebugString prints the tree with nested information
// to allow an eyeball check on the tree balance.
func (t *node32) DebugString(indent int) string {
	s := ""
	if t.left != nil {
		s = s + t.left.DebugString(indent+1)
	}
	for i := 0; i < indent; i++ {
		s = s + "    "
	}
	s = s + fmt.Sprintf("%v=%v:%d\n", t.key, t.data, t.height_)
	if t.right != nil {
		s = s + t.right.DebugString(indent+1)
	}
	return s
}

"""



```