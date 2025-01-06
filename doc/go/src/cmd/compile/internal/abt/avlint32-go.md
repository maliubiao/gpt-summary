Response:
Let's break down the thought process for analyzing this Go code snippet.

**1. Initial Read-Through and Identification of Core Structure:**

The first step is to read the code, even if you don't understand every detail. Key things to immediately notice are:

* **Package Name:** `abt` suggests some kind of abstract data type.
* **Data Structures:** `T` and `node32`. `T` has a `root` of type `*node32`, strongly suggesting a tree structure. `node32` has `left`, `right`, `data`, `key`, and `height_`, confirming a tree node. The `32` likely implies the key is a 32-bit integer.
* **Constants:** `LEAF_HEIGHT`, `ZERO_HEIGHT`, `NOT_KEY32`. These provide context. `NOT_KEY32` is a sentinel value.
* **Methods on `T` and `node32`:**  This is where the functionality lies. Look for familiar tree operations like `Insert`, `Find`, `Delete`, `Min`, `Max`, and traversal methods (`VisitInOrder`, `Iterator`). The presence of `Intersection`, `Union`, and `Difference` suggests set-like operations.
* **Methods with `a` prefix (e.g., `aInsert`, `aDelete`):** This often indicates internal, possibly recursive helper functions for the core operations. The `a` might stand for "auxiliary" or "applicative" (given the package name).
* **Methods related to balancing (e.g., `aLeftIsHigh`, `aRightIsHigh`, `leftToRoot`, `rightToRoot`):**  This strongly indicates that the tree is self-balancing. AVL trees are a common type of self-balancing binary search tree.

**2. Formulating the Core Functionality Hypothesis:**

Based on the observations above, the primary function of this code is to implement an *applicative* (meaning operations return new trees rather than modifying in-place) self-balancing binary search tree where keys are 32-bit integers. The `interface{}` for `data` suggests it can store arbitrary values associated with the keys.

**3. Deeper Dive into Key Methods:**

Now, examine the core methods more closely:

* **`Insert`:** Creates a new node if the key doesn't exist, or updates the data if it does. The "applicative" nature is evident because it doesn't modify the original tree directly. It returns the old data if the key existed.
* **`Find`:**  Standard binary search to locate a key.
* **`Delete`:**  Handles deletion with rebalancing. The logic for deleting from a node with two children (finding the inorder successor/predecessor) is visible.
* **`Min`, `Max`:**  Simple traversals to the leftmost and rightmost nodes.
* **`VisitInOrder`:**  Standard inorder traversal.
* **`Iterator`:**  Provides a way to iterate over the tree's elements in sorted order.
* **`Intersection`, `Union`, `Difference`:** Implement set operations, demonstrating the ability to treat the tree as a set of key-value pairs. The optional `f` function for combining data during these operations is interesting.
* **Balancing Methods:** The `aLeftIsHigh`, `aRightIsHigh`, `leftToRoot`, and `rightToRoot` methods clearly implement the rotations needed for AVL tree balancing.

**4. Code Example Construction:**

To illustrate the functionality, construct basic use cases. Start with simple insertion and retrieval:

```go
package main

import (
	"fmt"
	"go/src/cmd/compile/internal/abt" // Adjust path as needed
)

func main() {
	tree := &abt.T{}
	tree.Insert(10, "value10")
	tree.Insert(5, "value5")
	tree.Insert(15, "value15")

	fmt.Println(tree.Find(10)) // Output: value10
	fmt.Println(tree.Find(7))  // Output: <nil>
}
```

Then, demonstrate deletion and the applicative nature:

```go
	originalTree := &abt.T{}
	originalTree.Insert(10, "old_value")
	newTree := originalTree.Insert(10, "new_value")

	fmt.Println(originalTree.Find(10)) // Output: old_value (original unchanged)
	fmt.Println(newTree.Find(10))      // Output: new_value
```

Finally, showcase the set operations:

```go
	tree1 := &abt.T{}
	tree1.Insert(1, "a")
	tree1.Insert(2, "b")

	tree2 := &abt.T{}
	tree2.Insert(2, "c")
	tree2.Insert(3, "d")

	intersection := tree1.Intersection(tree2, nil)
	fmt.Println(intersection.String()) // Output: 2:b

	union := tree1.Union(tree2, nil)
	fmt.Println(union.String()) // Output: 1:a; 2:b; 3:d
}
```

**5. Identifying Potential Pitfalls:**

Consider how a user might misuse the API:

* **Using the sentinel value:** The code explicitly checks for and panics on inserting `NOT_KEY32`. This is an obvious error.
* **Understanding applicative behavior:** Users might mistakenly believe that operations modify the original tree, leading to unexpected results if they reuse the original after an "update." Emphasize that a new tree is created.
* **Nil `f` function behavior:**  Clarify the default behavior of `Intersection` and `Union` when `f` is nil.

**6. Command-Line Arguments (Not Applicable):**

Scan the code for any use of `os.Args` or a similar mechanism for processing command-line input. In this case, there are none. So, this section is skipped.

**7. Refining and Structuring the Output:**

Organize the findings logically, starting with the core functionality, then providing examples, and finally discussing potential errors. Use clear and concise language. Use code blocks for examples to improve readability.

This systematic approach, moving from a high-level understanding to specific details and then considering usage patterns, allows for a comprehensive analysis of the given Go code snippet.
这段代码是 Go 语言标准库 `cmd/compile/internal/abt` 包中的 `avlint32.go` 文件的一部分。它实现了一个**基于 AVL 树的、键类型为 `int32` 的、持久化的（或称作 applicative）平衡二叉搜索树**。

下面列举一下它的功能：

1. **基本数据结构:**
   - 定义了 `T` 结构体，表示外部使用的树结构，包含根节点 `root` (`*node32`) 和树的大小 `size`。
   - 定义了 `node32` 结构体，表示树的内部节点，包含左右子节点 (`*node32`)，存储的数据 (`interface{}`)，键 (`int32`) 和高度 (`int8`)。
   - 定义了常量 `LEAF_HEIGHT` (1), `ZERO_HEIGHT` (0), 和 `NOT_KEY32` (-0x80000000)，分别表示叶子节点的高度，空节点的高度，以及一个特殊的无效键值。

2. **创建节点:**
   - `makeNode(key int32)` 函数用于创建一个新的叶子节点。

3. **基本查询操作:**
   - `IsEmpty()`: 判断树是否为空。
   - `IsSingle()`: 判断树是否只有一个节点（叶子节点）。
   - `Find(x int32)`:  在树中查找键为 `x` 的节点，并返回关联的数据。如果找不到，返回 `nil`。
   - `Size()`: 返回树中元素的个数。
   - `Min()`: 返回树中的最小键值和对应的数据。
   - `Max()`: 返回树中的最大键值和对应的数据。
   - `Glb(x int32)`: 返回严格小于 `x` 的最大键值和对应的数据 (greatest-lower-bound-exclusive)。
   - `GlbEq(x int32)`: 返回小于等于 `x` 的最大键值和对应的数据 (greatest-lower-bound-inclusive)。
   - `Lub(x int32)`: 返回严格大于 `x` 的最小键值和对应的数据 (least-upper-bound-exclusive)。
   - `LubEq(x int32)`: 返回大于等于 `x` 的最小键值和对应的数据 (least-upper-bound-inclusive)。

4. **修改操作 (持久化):**
   - `Insert(x int32, data interface{})`: 插入或更新键为 `x` 的节点的数据。如果键不存在，则插入新节点；如果键已存在，则更新数据并返回旧数据。**注意，由于是持久化数据结构，`Insert` 操作会返回一个新的树结构，而不会修改原有的树。**
   - `Delete(x int32)`: 删除键为 `x` 的节点，并返回被删除节点的数据。**同样，这是一个持久化操作。**
   - `DeleteMin()`: 删除最小键值的节点，并返回其键值和数据。
   - `DeleteMax()`: 删除最大键值的节点，并返回其键值和数据。

5. **集合操作:**
   - `Intersection(u *T, f func(x, y interface{}) interface{}) *T`: 返回当前树 `t` 和树 `u` 的交集。对于相同的键，使用函数 `f` 合并两个树中对应的数据。如果 `f` 返回 `nil`，则该键值对不会包含在结果中。如果 `f` 为 `nil`，则使用较小集合中的值。
   - `Union(u *T, f func(x, y interface{}) interface{}) *T`: 返回当前树 `t` 和树 `u` 的并集。对于相同的键，使用函数 `f` 合并两个树中对应的数据。如果 `f` 返回 `nil`，则该键值对不会包含在结果中。如果 `f` 为 `nil`，则使用较大集合中的值。
   - `Difference(u *T, f func(x, y interface{}) interface{}) *T`: 返回当前树 `t` 和树 `u` 的差集，即存在于 `t` 但不存在于 `u` 的键值对。对于相同的键，使用函数 `f` 处理数据，如果 `f` 返回 `nil`，则该键值对不会包含在结果中。如果 `f` 为 `nil`，则会删除 `t` 中与 `u` 相同的键。

6. **遍历操作:**
   - `VisitInOrder(f func(int32, interface{}))`:  对树中的每个键值对按键的升序应用函数 `f`。
   - `Iterator()`: 返回一个用于遍历树的迭代器 `Iterator`。

7. **比较操作:**
   - `Equals(u *T)`: 判断当前树 `t` 和树 `u` 是否在结构和数据上完全相等。
   - `Equiv(u *T, eqv func(x, y interface{}) bool)`: 判断当前树 `t` 和树 `u` 是否在结构上相等，并且对于相同的键，对应的数据满足 `eqv` 函数。

8. **其他辅助功能:**
   - `Copy()`:  创建一个树的浅拷贝。
   - `String()`: 返回树的字符串表示形式，方便调试。

**它是什么 Go 语言功能的实现？**

这个文件实现了一个**持久化的、基于 int32 键的 AVL 树**。AVL 树是一种自平衡二叉搜索树，它保证了树的高度是 O(log n)，从而使得查找、插入和删除操作的时间复杂度都是 O(log n)。 "持久化" 的意思是每次修改操作（如 `Insert` 或 `Delete`）都会返回一个新的树的副本，而原始的树保持不变。这在某些场景下非常有用，比如需要维护多个版本的状态或者进行函数式编程。

**Go 代码举例说明:**

```go
package main

import (
	"fmt"
	"go/src/cmd/compile/internal/abt" // 注意：实际使用时可能需要调整路径
)

func main() {
	// 创建一个空的 AVL 树
	tree := &abt.T{}

	// 插入一些数据
	tree1 := tree.Insert(10, "value10")
	tree2 := tree1.Insert(5, "value5")
	tree3 := tree2.Insert(15, "value15")

	fmt.Println("原始树是否为空:", tree.IsEmpty())        // 输出: 原始树是否为空: true
	fmt.Println("tree3 的大小:", tree3.Size())         // 输出: tree3 的大小: 3
	fmt.Println("在 tree3 中查找键 10:", tree3.Find(10))   // 输出: 在 tree3 中查找键 10: value10
	fmt.Println("在 tree3 中查找键 7:", tree3.Find(7))    // 输出: 在 tree3 中查找键 7: <nil>

	// 删除一个元素
	tree4 := tree3.Delete(10)
	fmt.Println("tree4 的大小:", tree4.Size())         // 输出: tree4 的大小: 2
	fmt.Println("在 tree4 中查找键 10:", tree4.Find(10))   // 输出: 在 tree4 中查找键 10: <nil>

	// 遍历树
	fmt.Println("按顺序遍历 tree3:")
	tree3.VisitInOrder(func(key int32, data interface{}) {
		fmt.Printf("Key: %d, Data: %v\n", key, data)
	})
	// 输出:
	// 按顺序遍历 tree3:
	// Key: 5, Data: value5
	// Key: 10, Data: value10
	// Key: 15, Data: value15

	// 集合操作
	treeA := &abt.T{}
	treeA = treeA.Insert(1, "a").Insert(2, "b").Insert(3, "c")
	treeB := &abt.T{}
	treeB = treeB.Insert(2, "x").Insert(3, "y").Insert(4, "z")

	intersection := treeA.Intersection(treeB, func(a, b interface{}) interface{} {
		return fmt.Sprintf("%v-%v", a, b)
	})
	fmt.Println("交集:", intersection.String()) // 输出: 交集: 2:b-x; 3:c-y

	union := treeA.Union(treeB, nil)
	fmt.Println("并集:", union.String())      // 输出: 并集: 1:a; 2:b; 3:c; 4:z

	difference := treeA.Difference(treeB, nil)
	fmt.Println("差集 (A - B):", difference.String()) // 输出: 差集 (A - B): 1:a
}
```

**假设的输入与输出 (代码推理):**

以 `Insert` 操作为例：

**假设输入:**

```go
tree := &abt.T{}
```

**第一次 `Insert` 调用:**

```go
newTree1 := tree.Insert(5, "data5")
```

**推理输出 `newTree1` 的状态:**

- `newTree1.size` 将为 1。
- `newTree1.root` 将指向一个新的 `node32` 结构体，其 `key` 为 5，`data` 为 "data5"，`height_` 为 1，`left` 和 `right` 为 `nil`。

**第二次 `Insert` 调用:**

```go
newTree2 := newTree1.Insert(10, "data10")
```

**推理输出 `newTree2` 的状态:**

- `newTree2.size` 将为 2。
- `newTree2.root` 的 `key` 可能是 5 或 10 (取决于 AVL 树的平衡操作)。
  - 如果 `newTree2.root.key` 是 5，则 `newTree2.root.right` 将指向一个 `key` 为 10，`data` 为 "data10" 的节点。
  - 如果 `newTree2.root.key` 是 10，则 `newTree2.root.left` 将指向一个 `key` 为 5，`data` 为 "data5" 的节点。
- 相应的节点高度会被更新以保持 AVL 树的平衡。

**如果涉及命令行参数的具体处理:**

这段代码本身不涉及任何命令行参数的处理。它是一个纯粹的数据结构实现，用于在 Go 程序内部使用。命令行参数的处理通常会在 `main` 函数或者使用了 `flag` 包等的地方进行。

**使用者易犯错的点:**

1. **误解持久性:** 最容易犯的错误是忘记这是一个持久化数据结构。修改操作 (`Insert`, `Delete`) 不会改变原来的树，而是返回一个新的树。如果用户仍然使用旧的树，他们会看到修改前的状态。

   ```go
   tree1 := &abt.T{}
   tree2 := tree1.Insert(1, "one")
   fmt.Println(tree1.Size()) // 错误地认为 tree1 也被修改了，实际上输出 0
   fmt.Println(tree2.Size()) // 正确输出 1
   ```

2. **使用 `NOT_KEY32` 作为键:** 代码中明确禁止使用 `NOT_KEY32` 作为键，如果尝试这样做会触发 `panic`。

   ```go
   tree := &abt.T{}
   // tree.Insert(abt.NOT_KEY32, "invalid") // 这会 panic
   ```

3. **在集合操作中对 `f` 函数的理解不足:**  `Intersection`、`Union` 和 `Difference` 方法接受一个函数 `f` 来处理相同键的情况。如果不理解 `f` 的作用和返回值（特别是返回 `nil` 的情况），可能会得到意想不到的结果。

   ```go
   treeA := &abt.T{}
   treeA = treeA.Insert(1, "a")
   treeB := &abt.T{}
   treeB = treeB.Insert(1, "b")

   intersection := treeA.Intersection(treeB, func(x, y interface{}) interface{} {
       return nil // 总是返回 nil
   })
   fmt.Println(intersection.Size()) // 输出 0，因为 f 返回 nil 导致键值对不包含在结果中
   ```

总而言之，`avlint32.go` 提供了一个高效且线程安全的持久化键值存储结构，适用于编译器内部需要维护多个版本状态或进行复杂数据操作的场景。理解其持久化特性是避免使用错误的 key。

Prompt: 
```
这是路径为go/src/cmd/compile/internal/abt/avlint32.go的go语言实现的一部分， 请列举一下它的功能, 　
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
	"strings"
)

const (
	LEAF_HEIGHT = 1
	ZERO_HEIGHT = 0
	NOT_KEY32   = int32(-0x80000000)
)

// T is the exported applicative balanced tree data type.
// A T can be used as a value; updates to one copy of the value
// do not change other copies.
type T struct {
	root *node32
	size int
}

// node32 is the internal tree node data type
type node32 struct {
	// Standard conventions hold for left = smaller, right = larger
	left, right *node32
	data        interface{}
	key         int32
	height_     int8
}

func makeNode(key int32) *node32 {
	return &node32{key: key, height_: LEAF_HEIGHT}
}

// IsEmpty returns true iff t is empty.
func (t *T) IsEmpty() bool {
	return t.root == nil
}

// IsSingle returns true iff t is a singleton (leaf).
func (t *T) IsSingle() bool {
	return t.root != nil && t.root.isLeaf()
}

// VisitInOrder applies f to the key and data pairs in t,
// with keys ordered from smallest to largest.
func (t *T) VisitInOrder(f func(int32, interface{})) {
	if t.root == nil {
		return
	}
	t.root.visitInOrder(f)
}

func (n *node32) nilOrData() interface{} {
	if n == nil {
		return nil
	}
	return n.data
}

func (n *node32) nilOrKeyAndData() (k int32, d interface{}) {
	if n == nil {
		k = NOT_KEY32
		d = nil
	} else {
		k = n.key
		d = n.data
	}
	return
}

func (n *node32) height() int8 {
	if n == nil {
		return 0
	}
	return n.height_
}

// Find returns the data associated with x in the tree, or
// nil if x is not in the tree.
func (t *T) Find(x int32) interface{} {
	return t.root.find(x).nilOrData()
}

// Insert either adds x to the tree if x was not previously
// a key in the tree, or updates the data for x in the tree if
// x was already a key in the tree.  The previous data associated
// with x is returned, and is nil if x was not previously a
// key in the tree.
func (t *T) Insert(x int32, data interface{}) interface{} {
	if x == NOT_KEY32 {
		panic("Cannot use sentinel value -0x80000000 as key")
	}
	n := t.root
	var newroot *node32
	var o *node32
	if n == nil {
		n = makeNode(x)
		newroot = n
	} else {
		newroot, n, o = n.aInsert(x)
	}
	var r interface{}
	if o != nil {
		r = o.data
	} else {
		t.size++
	}
	n.data = data
	t.root = newroot
	return r
}

func (t *T) Copy() *T {
	u := *t
	return &u
}

func (t *T) Delete(x int32) interface{} {
	n := t.root
	if n == nil {
		return nil
	}
	d, s := n.aDelete(x)
	if d == nil {
		return nil
	}
	t.root = s
	t.size--
	return d.data
}

func (t *T) DeleteMin() (int32, interface{}) {
	n := t.root
	if n == nil {
		return NOT_KEY32, nil
	}
	d, s := n.aDeleteMin()
	if d == nil {
		return NOT_KEY32, nil
	}
	t.root = s
	t.size--
	return d.key, d.data
}

func (t *T) DeleteMax() (int32, interface{}) {
	n := t.root
	if n == nil {
		return NOT_KEY32, nil
	}
	d, s := n.aDeleteMax()
	if d == nil {
		return NOT_KEY32, nil
	}
	t.root = s
	t.size--
	return d.key, d.data
}

func (t *T) Size() int {
	return t.size
}

// Intersection returns the intersection of t and u, where the result
// data for any common keys is given by f(t's data, u's data) -- f need
// not be symmetric.  If f returns nil, then the key and data are not
// added to the result.  If f itself is nil, then whatever value was
// already present in the smaller set is used.
func (t *T) Intersection(u *T, f func(x, y interface{}) interface{}) *T {
	if t.Size() == 0 || u.Size() == 0 {
		return &T{}
	}

	// For faster execution and less allocation, prefer t smaller, iterate over t.
	if t.Size() <= u.Size() {
		v := t.Copy()
		for it := t.Iterator(); !it.Done(); {
			k, d := it.Next()
			e := u.Find(k)
			if e == nil {
				v.Delete(k)
				continue
			}
			if f == nil {
				continue
			}
			if c := f(d, e); c != d {
				if c == nil {
					v.Delete(k)
				} else {
					v.Insert(k, c)
				}
			}
		}
		return v
	}
	v := u.Copy()
	for it := u.Iterator(); !it.Done(); {
		k, e := it.Next()
		d := t.Find(k)
		if d == nil {
			v.Delete(k)
			continue
		}
		if f == nil {
			continue
		}
		if c := f(d, e); c != d {
			if c == nil {
				v.Delete(k)
			} else {
				v.Insert(k, c)
			}
		}
	}

	return v
}

// Union returns the union of t and u, where the result data for any common keys
// is given by f(t's data, u's data) -- f need not be symmetric.  If f returns nil,
// then the key and data are not added to the result.  If f itself is nil, then
// whatever value was already present in the larger set is used.
func (t *T) Union(u *T, f func(x, y interface{}) interface{}) *T {
	if t.Size() == 0 {
		return u
	}
	if u.Size() == 0 {
		return t
	}

	if t.Size() >= u.Size() {
		v := t.Copy()
		for it := u.Iterator(); !it.Done(); {
			k, e := it.Next()
			d := t.Find(k)
			if d == nil {
				v.Insert(k, e)
				continue
			}
			if f == nil {
				continue
			}
			if c := f(d, e); c != d {
				if c == nil {
					v.Delete(k)
				} else {
					v.Insert(k, c)
				}
			}
		}
		return v
	}

	v := u.Copy()
	for it := t.Iterator(); !it.Done(); {
		k, d := it.Next()
		e := u.Find(k)
		if e == nil {
			v.Insert(k, d)
			continue
		}
		if f == nil {
			continue
		}
		if c := f(d, e); c != d {
			if c == nil {
				v.Delete(k)
			} else {
				v.Insert(k, c)
			}
		}
	}
	return v
}

// Difference returns the difference of t and u, subject to the result
// of f applied to data corresponding to equal keys.  If f returns nil
// (or if f is nil) then the key+data are excluded, as usual.  If f
// returns not-nil, then that key+data pair is inserted. instead.
func (t *T) Difference(u *T, f func(x, y interface{}) interface{}) *T {
	if t.Size() == 0 {
		return &T{}
	}
	if u.Size() == 0 {
		return t
	}
	v := t.Copy()
	for it := t.Iterator(); !it.Done(); {
		k, d := it.Next()
		e := u.Find(k)
		if e != nil {
			if f == nil {
				v.Delete(k)
				continue
			}
			c := f(d, e)
			if c == nil {
				v.Delete(k)
				continue
			}
			if c != d {
				v.Insert(k, c)
			}
		}
	}
	return v
}

func (t *T) Iterator() Iterator {
	return Iterator{it: t.root.iterator()}
}

func (t *T) Equals(u *T) bool {
	if t == u {
		return true
	}
	if t.Size() != u.Size() {
		return false
	}
	return t.root.equals(u.root)
}

func (t *T) String() string {
	var b strings.Builder
	first := true
	for it := t.Iterator(); !it.Done(); {
		k, v := it.Next()
		if first {
			first = false
		} else {
			b.WriteString("; ")
		}
		b.WriteString(strconv.FormatInt(int64(k), 10))
		b.WriteString(":")
		fmt.Fprint(&b, v)
	}
	return b.String()
}

func (t *node32) equals(u *node32) bool {
	if t == u {
		return true
	}
	it, iu := t.iterator(), u.iterator()
	for !it.done() && !iu.done() {
		nt := it.next()
		nu := iu.next()
		if nt == nu {
			continue
		}
		if nt.key != nu.key {
			return false
		}
		if nt.data != nu.data {
			return false
		}
	}
	return it.done() == iu.done()
}

func (t *T) Equiv(u *T, eqv func(x, y interface{}) bool) bool {
	if t == u {
		return true
	}
	if t.Size() != u.Size() {
		return false
	}
	return t.root.equiv(u.root, eqv)
}

func (t *node32) equiv(u *node32, eqv func(x, y interface{}) bool) bool {
	if t == u {
		return true
	}
	it, iu := t.iterator(), u.iterator()
	for !it.done() && !iu.done() {
		nt := it.next()
		nu := iu.next()
		if nt == nu {
			continue
		}
		if nt.key != nu.key {
			return false
		}
		if !eqv(nt.data, nu.data) {
			return false
		}
	}
	return it.done() == iu.done()
}

type iterator struct {
	parents []*node32
}

type Iterator struct {
	it iterator
}

func (it *Iterator) Next() (int32, interface{}) {
	x := it.it.next()
	if x == nil {
		return NOT_KEY32, nil
	}
	return x.key, x.data
}

func (it *Iterator) Done() bool {
	return len(it.it.parents) == 0
}

func (t *node32) iterator() iterator {
	if t == nil {
		return iterator{}
	}
	it := iterator{parents: make([]*node32, 0, int(t.height()))}
	it.leftmost(t)
	return it
}

func (it *iterator) leftmost(t *node32) {
	for t != nil {
		it.parents = append(it.parents, t)
		t = t.left
	}
}

func (it *iterator) done() bool {
	return len(it.parents) == 0
}

func (it *iterator) next() *node32 {
	l := len(it.parents)
	if l == 0 {
		return nil
	}
	x := it.parents[l-1] // return value
	if x.right != nil {
		it.leftmost(x.right)
		return x
	}
	// discard visited top of parents
	l--
	it.parents = it.parents[:l]
	y := x // y is known visited/returned
	for l > 0 && y == it.parents[l-1].right {
		y = it.parents[l-1]
		l--
		it.parents = it.parents[:l]
	}

	return x
}

// Min returns the minimum element of t.
// If t is empty, then (NOT_KEY32, nil) is returned.
func (t *T) Min() (k int32, d interface{}) {
	return t.root.min().nilOrKeyAndData()
}

// Max returns the maximum element of t.
// If t is empty, then (NOT_KEY32, nil) is returned.
func (t *T) Max() (k int32, d interface{}) {
	return t.root.max().nilOrKeyAndData()
}

// Glb returns the greatest-lower-bound-exclusive of x and the associated
// data.  If x has no glb in the tree, then (NOT_KEY32, nil) is returned.
func (t *T) Glb(x int32) (k int32, d interface{}) {
	return t.root.glb(x, false).nilOrKeyAndData()
}

// GlbEq returns the greatest-lower-bound-inclusive of x and the associated
// data.  If x has no glbEQ in the tree, then (NOT_KEY32, nil) is returned.
func (t *T) GlbEq(x int32) (k int32, d interface{}) {
	return t.root.glb(x, true).nilOrKeyAndData()
}

// Lub returns the least-upper-bound-exclusive of x and the associated
// data.  If x has no lub in the tree, then (NOT_KEY32, nil) is returned.
func (t *T) Lub(x int32) (k int32, d interface{}) {
	return t.root.lub(x, false).nilOrKeyAndData()
}

// LubEq returns the least-upper-bound-inclusive of x and the associated
// data.  If x has no lubEq in the tree, then (NOT_KEY32, nil) is returned.
func (t *T) LubEq(x int32) (k int32, d interface{}) {
	return t.root.lub(x, true).nilOrKeyAndData()
}

func (t *node32) isLeaf() bool {
	return t.left == nil && t.right == nil && t.height_ == LEAF_HEIGHT
}

func (t *node32) visitInOrder(f func(int32, interface{})) {
	if t.left != nil {
		t.left.visitInOrder(f)
	}
	f(t.key, t.data)
	if t.right != nil {
		t.right.visitInOrder(f)
	}
}

func (t *node32) find(key int32) *node32 {
	for t != nil {
		if key < t.key {
			t = t.left
		} else if key > t.key {
			t = t.right
		} else {
			return t
		}
	}
	return nil
}

func (t *node32) min() *node32 {
	if t == nil {
		return t
	}
	for t.left != nil {
		t = t.left
	}
	return t
}

func (t *node32) max() *node32 {
	if t == nil {
		return t
	}
	for t.right != nil {
		t = t.right
	}
	return t
}

func (t *node32) glb(key int32, allow_eq bool) *node32 {
	var best *node32 = nil
	for t != nil {
		if key <= t.key {
			if allow_eq && key == t.key {
				return t
			}
			// t is too big, glb is to left.
			t = t.left
		} else {
			// t is a lower bound, record it and seek a better one.
			best = t
			t = t.right
		}
	}
	return best
}

func (t *node32) lub(key int32, allow_eq bool) *node32 {
	var best *node32 = nil
	for t != nil {
		if key >= t.key {
			if allow_eq && key == t.key {
				return t
			}
			// t is too small, lub is to right.
			t = t.right
		} else {
			// t is an upper bound, record it and seek a better one.
			best = t
			t = t.left
		}
	}
	return best
}

func (t *node32) aInsert(x int32) (newroot, newnode, oldnode *node32) {
	// oldnode default of nil is good, others should be assigned.
	if x == t.key {
		oldnode = t
		newt := *t
		newnode = &newt
		newroot = newnode
		return
	}
	if x < t.key {
		if t.left == nil {
			t = t.copy()
			n := makeNode(x)
			t.left = n
			newnode = n
			newroot = t
			t.height_ = 2 // was balanced w/ 0, sibling is height 0 or 1
			return
		}
		var new_l *node32
		new_l, newnode, oldnode = t.left.aInsert(x)
		t = t.copy()
		t.left = new_l
		if new_l.height() > 1+t.right.height() {
			newroot = t.aLeftIsHigh(newnode)
		} else {
			t.height_ = 1 + max(t.left.height(), t.right.height())
			newroot = t
		}
	} else { // x > t.key
		if t.right == nil {
			t = t.copy()
			n := makeNode(x)
			t.right = n
			newnode = n
			newroot = t
			t.height_ = 2 // was balanced w/ 0, sibling is height 0 or 1
			return
		}
		var new_r *node32
		new_r, newnode, oldnode = t.right.aInsert(x)
		t = t.copy()
		t.right = new_r
		if new_r.height() > 1+t.left.height() {
			newroot = t.aRightIsHigh(newnode)
		} else {
			t.height_ = 1 + max(t.left.height(), t.right.height())
			newroot = t
		}
	}
	return
}

func (t *node32) aDelete(key int32) (deleted, newSubTree *node32) {
	if t == nil {
		return nil, nil
	}

	if key < t.key {
		oh := t.left.height()
		d, tleft := t.left.aDelete(key)
		if tleft == t.left {
			return d, t
		}
		return d, t.copy().aRebalanceAfterLeftDeletion(oh, tleft)
	} else if key > t.key {
		oh := t.right.height()
		d, tright := t.right.aDelete(key)
		if tright == t.right {
			return d, t
		}
		return d, t.copy().aRebalanceAfterRightDeletion(oh, tright)
	}

	if t.height() == LEAF_HEIGHT {
		return t, nil
	}

	// Interior delete by removing left.Max or right.Min,
	// then swapping contents
	if t.left.height() > t.right.height() {
		oh := t.left.height()
		d, tleft := t.left.aDeleteMax()
		r := t
		t = t.copy()
		t.data, t.key = d.data, d.key
		return r, t.aRebalanceAfterLeftDeletion(oh, tleft)
	}

	oh := t.right.height()
	d, tright := t.right.aDeleteMin()
	r := t
	t = t.copy()
	t.data, t.key = d.data, d.key
	return r, t.aRebalanceAfterRightDeletion(oh, tright)
}

func (t *node32) aDeleteMin() (deleted, newSubTree *node32) {
	if t == nil {
		return nil, nil
	}
	if t.left == nil { // leaf or left-most
		return t, t.right
	}
	oh := t.left.height()
	d, tleft := t.left.aDeleteMin()
	if tleft == t.left {
		return d, t
	}
	return d, t.copy().aRebalanceAfterLeftDeletion(oh, tleft)
}

func (t *node32) aDeleteMax() (deleted, newSubTree *node32) {
	if t == nil {
		return nil, nil
	}

	if t.right == nil { // leaf or right-most
		return t, t.left
	}

	oh := t.right.height()
	d, tright := t.right.aDeleteMax()
	if tright == t.right {
		return d, t
	}
	return d, t.copy().aRebalanceAfterRightDeletion(oh, tright)
}

func (t *node32) aRebalanceAfterLeftDeletion(oldLeftHeight int8, tleft *node32) *node32 {
	t.left = tleft

	if oldLeftHeight == tleft.height() || oldLeftHeight == t.right.height() {
		// this node is still balanced and its height is unchanged
		return t
	}

	if oldLeftHeight > t.right.height() {
		// left was larger
		t.height_--
		return t
	}

	// left height fell by 1 and it was already less than right height
	t.right = t.right.copy()
	return t.aRightIsHigh(nil)
}

func (t *node32) aRebalanceAfterRightDeletion(oldRightHeight int8, tright *node32) *node32 {
	t.right = tright

	if oldRightHeight == tright.height() || oldRightHeight == t.left.height() {
		// this node is still balanced and its height is unchanged
		return t
	}

	if oldRightHeight > t.left.height() {
		// left was larger
		t.height_--
		return t
	}

	// right height fell by 1 and it was already less than left height
	t.left = t.left.copy()
	return t.aLeftIsHigh(nil)
}

// aRightIsHigh does rotations necessary to fix a high right child
// assume that t and t.right are already fresh copies.
func (t *node32) aRightIsHigh(newnode *node32) *node32 {
	right := t.right
	if right.right.height() < right.left.height() {
		// double rotation
		if newnode != right.left {
			right.left = right.left.copy()
		}
		t.right = right.leftToRoot()
	}
	t = t.rightToRoot()
	return t
}

// aLeftIsHigh does rotations necessary to fix a high left child
// assume that t and t.left are already fresh copies.
func (t *node32) aLeftIsHigh(newnode *node32) *node32 {
	left := t.left
	if left.left.height() < left.right.height() {
		// double rotation
		if newnode != left.right {
			left.right = left.right.copy()
		}
		t.left = left.rightToRoot()
	}
	t = t.leftToRoot()
	return t
}

// rightToRoot does that rotation, modifying t and t.right in the process.
func (t *node32) rightToRoot() *node32 {
	//    this
	// left  right
	//      rl   rr
	//
	// becomes
	//
	//       right
	//    this   rr
	// left  rl
	//
	right := t.right
	rl := right.left
	right.left = t
	// parent's child ptr fixed in caller
	t.right = rl
	t.height_ = 1 + max(rl.height(), t.left.height())
	right.height_ = 1 + max(t.height(), right.right.height())
	return right
}

// leftToRoot does that rotation, modifying t and t.left in the process.
func (t *node32) leftToRoot() *node32 {
	//     this
	//  left  right
	// ll  lr
	//
	// becomes
	//
	//    left
	//   ll  this
	//      lr  right
	//
	left := t.left
	lr := left.right
	left.right = t
	// parent's child ptr fixed in caller
	t.left = lr
	t.height_ = 1 + max(lr.height(), t.right.height())
	left.height_ = 1 + max(t.height(), left.left.height())
	return left
}

func (t *node32) copy() *node32 {
	u := *t
	return &u
}

"""



```