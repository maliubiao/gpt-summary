Response: My thinking process to analyze the Go code and fulfill the request goes like this:

1. **Understand the Goal:** The primary goal is to understand the functionality of the provided Go code snippet. The prompt explicitly asks for summarization, identification of the Go feature being tested, code examples, explanation of logic (with input/output), handling of command-line arguments (if any), and common mistakes.

2. **Initial Scan and Identification of the Core Feature:** I first scanned the code for keywords and patterns. The presence of `PushFront`, `PushBack`, `Remove`, `MoveToFront`, `MoveToBack`, `InsertBefore`, `InsertAfter`, `Front`, `Next`, and `Len` strongly suggests that the code is related to implementing or testing a **doubly linked list**. The import of a local package `"./a"` and the frequent calls to functions like `a.New`, `a.CheckListPointers`, and `a.CheckListLen` reinforce this idea, suggesting that the `a` package likely contains the implementation of the linked list. The presence of generics (`[string]`, `[int]`) indicates the code is testing a generic linked list implementation.

3. **Analyze Individual Test Functions:**  I then went through each `Test...` function to understand the specific scenarios being tested.

    * **`TestList()`:** This function clearly tests the basic operations of a doubly linked list: adding elements to the front and back, moving elements, removing elements, and iterating through the list. The calls to `a.CheckListPointers` with expected list states are key to understanding the intended behavior.

    * **`TestExtending()`:** This function tests the functionality of merging or appending lists using `PushBackList` and `PushFrontList`. It also tests the behavior of appending a list to itself.

    * **`TestRemove()`:** This focuses specifically on the `Remove` operation, verifying the list's state after removing elements.

    * **`TestIssue4103()` and `TestIssue6349()`:** These tests are named after specific issues, suggesting they are regression tests for identified bugs. `TestIssue4103` checks that removing an element from a list it doesn't belong to doesn't cause errors. `TestIssue6349` checks the state of a removed element.

    * **`TestMove()`:** This tests the `MoveAfter` and `MoveBefore` operations, verifying correct element placement.

    * **`TestZeroList()`:** This verifies that the list implementation works correctly even when initialized with `new(a.List[int])` (a zero value).

    * **`TestInsertBeforeUnknownMark()`, `TestInsertAfterUnknownMark()`, `TestMoveUnknownMark()`:** These tests ensure that operations don't modify the list if the provided "mark" element isn't actually in the list. This is important for robustness.

    * **`TestTransform()`:** This function introduces a higher-order function aspect, demonstrating a transformation operation on the list's elements using a provided function (`strconv.Itoa`).

4. **Synthesize the Functionality:** Based on the analysis of individual tests, I could confidently state that the code is testing a generic doubly linked list implementation.

5. **Provide a Code Example:**  To illustrate the usage, I created a simple example demonstrating the creation, addition, and iteration of a linked list. This provides a practical demonstration of the feature.

6. **Explain Code Logic with Input/Output:** I chose `TestList()` as a good candidate for detailed explanation because it covers many basic list operations. I selected a few key operations (PushFront, PushBack, Remove, MoveToFront) and described their effects on the list, providing hypothetical input and the expected output state of the list.

7. **Address Command-Line Arguments:** I scanned the `main()` function and the individual test functions. There were no uses of `os.Args` or the `flag` package, so I correctly concluded that the code doesn't handle command-line arguments.

8. **Identify Common Mistakes:**  Based on the tests provided (especially the "Issue" tests and the "UnknownMark" tests), I could infer potential pitfalls for users:
    * **Operating on elements from different lists:** The `TestIssue4103` example directly highlighted this.
    * **Assuming removed elements are still part of the list:** `TestIssue6349` demonstrates that a removed element is detached.
    * **Incorrectly using elements as markers:** The "UnknownMark" tests highlight the importance of using actual elements from the list as markers for `InsertBefore`, `InsertAfter`, `MoveAfter`, and `MoveBefore`.

9. **Structure the Response:**  Finally, I organized the information into the requested categories: functionality summary, Go feature identification, code example, logic explanation, command-line argument handling, and common mistakes. I aimed for clear and concise explanations with code examples where necessary.

By following this systematic approach, I could effectively analyze the Go code and provide a comprehensive answer that addressed all aspects of the prompt. The key was to break down the code into smaller, manageable parts (the individual test functions) and then synthesize the overall functionality from those parts.

好的，让我们来分析一下这段 Go 代码。

**功能归纳**

这段代码是用于测试一个实现了**泛型双向链表**功能的 Go 语言库。

具体来说，它测试了链表的以下核心操作：

* **创建链表:** `a.New[string]()`, `a.New[int]()`
* **在链表头部添加元素:** `l.PushFront("a")`, `l2.PushFront(1)`
* **在链表尾部添加元素:** `l2.PushBack(3)`, `l2.PushBack(600)`
* **移除链表中的元素:** `l.Remove(e)`
* **将元素移动到链表头部:** `l.MoveToFront(e)`
* **将元素移动到链表尾部:** `l.MoveToBack(e)`
* **在指定元素前插入新元素:** `l2.InsertBefore(2, e1)`
* **在指定元素后插入新元素:** `l2.InsertAfter(2, e1)`
* **链表的迭代:** 使用 `l2.Front()` 和 `e.Next()` 遍历链表
* **清空链表:** 通过迭代并移除元素
* **合并链表 (扩展):** `l3.PushBackList(l1)`, `l3.PushFrontList(l2)`
* **移动链表中的元素到指定元素的前后:** `l.MoveAfter(e3, e2)`, `l.MoveBefore(e2, e4)`
* **转换链表元素类型:** `a.Transform(l1, strconv.Itoa)`

辅助功能 (由 `a` 包提供，但在此代码中被调用):

* **检查链表指针是否正确:** `a.CheckListPointers(l, []*(a.Element[string]){e})`  这很可能是用于断言链表内部 `prev` 和 `next` 指针是否按照预期连接。
* **检查链表长度:** `a.CheckListLen(l, len(es))`

**Go 语言功能实现：泛型双向链表**

这段代码正在测试 Go 语言的**泛型 (Generics)** 功能在实现数据结构上的应用，特别是双向链表。 泛型允许我们编写可以处理多种数据类型的代码，而无需为每种类型都编写重复的代码。

**Go 代码示例 (假设 `a` 包的实现)**

为了更好地理解，以下是一个简化的 `a` 包中双向链表可能实现的示例：

```go
package a

import "fmt"

// Element represents an element in the linked list.
type Element[T any] struct {
	Value T
	next  *Element[T]
	prev  *Element[T]
}

// List represents a doubly linked list.
type List[T any] struct {
	head *Element[T]
	tail *Element[T]
	len  int
}

// New creates a new empty linked list.
func New[T any]() *List[T] {
	return &List[T]{}
}

// PushFront adds an element to the front of the list.
func (l *List[T]) PushFront(v T) *Element[T] {
	e := &Element[T]{Value: v}
	if l.head == nil {
		l.head = e
		l.tail = e
	} else {
		e.next = l.head
		l.head.prev = e
		l.head = e
	}
	l.len++
	return e
}

// PushBack adds an element to the back of the list.
func (l *List[T]) PushBack(v T) *Element[T] {
	e := &Element[T]{Value: v}
	if l.tail == nil {
		l.head = e
		l.tail = e
	} else {
		e.prev = l.tail
		l.tail.next = e
		l.tail = e
	}
	l.len++
	return e
}

// Remove removes an element from the list.
func (l *List[T]) Remove(e *Element[T]) {
	if e == nil {
		return
	}
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		l.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		l.tail = e.prev
	}
	e.next = nil // Avoid memory leaks
	e.prev = nil
	l.len--
}

// Front returns the first element of the list or nil if the list is empty.
func (l *List[T]) Front() *Element[T] {
	return l.head
}

// Next returns the next element in the list.
func (e *Element[T]) Next() *Element[T] {
	return e.next
}

// Len returns the number of elements in the list.
func (l *List[T]) Len() int {
	return l.len
}

// CheckListPointers is a test helper to verify list integrity.
func CheckListPointers[T any](l *List[T], expected []*Element[T]) {
	if l.len != len(expected) {
		panic(fmt.Sprintf("List length mismatch: got %d, want %d", l.len, len(expected)))
	}
	if l.len == 0 && l.head != nil || l.len == 0 && l.tail != nil {
		panic("Empty list has non-nil head or tail")
	}
	if l.len > 0 && l.head == nil || l.len > 0 && l.tail == nil {
		panic("Non-empty list has nil head or tail")
	}

	// Check forward pointers
	current := l.head
	for i, exp := range expected {
		if current != exp {
			panic(fmt.Sprintf("Forward pointer mismatch at index %d: got %p, want %p", i, current, exp))
		}
		current = current.next
	}
	if current != nil {
		panic("Forward iteration did not reach the end")
	}

	// Check backward pointers
	current = l.tail
	for i := len(expected) - 1; i >= 0; i-- {
		exp := expected[i]
		if current != exp {
			panic(fmt.Sprintf("Backward pointer mismatch at index %d: got %p, want %p", i, current, exp))
		}
		current = current.prev
	}
	if current != nil {
		panic("Backward iteration did not reach the beginning")
	}
}

// CheckListLen is a test helper to verify list length.
func CheckListLen[T any](l *List[T], expectedLen int) bool {
	if l.Len() != expectedLen {
		fmt.Printf("List length mismatch: got %d, want %d\n", l.Len(), expectedLen)
		return false
	}
	return true
}

// MoveToFront moves an element to the front of the list.
func (l *List[T]) MoveToFront(e *Element[T]) {
	if l.head == e || l.head == nil || e == nil {
		return
	}
	l.Remove(e)
	l.PushFront(e.Value)
}

// MoveToBack moves an element to the back of the list.
func (l *List[T]) MoveToBack(e *Element[T]) {
	if l.tail == e || l.tail == nil || e == nil {
		return
	}
	l.Remove(e)
	l.PushBack(e.Value)
}

// InsertBefore inserts a new element with value v before element mark.
func (l *List[T]) InsertBefore(v T, mark *Element[T]) *Element[T] {
	if mark == nil || mark.prev == nil {
		return l.PushFront(v)
	}
	e := &Element[T]{Value: v, next: mark, prev: mark.prev}
	mark.prev.next = e
	mark.prev = e
	l.len++
	return e
}

// InsertAfter inserts a new element with value v after element mark.
func (l *List[T]) InsertAfter(v T, mark *Element[T]) *Element[T] {
	if mark == nil || mark.next == nil {
		return l.PushBack(v)
	}
	e := &Element[T]{Value: v, prev: mark, next: mark.next}
	mark.next.prev = e
	mark.next = e
	l.len++
	return e
}

// PushBackList inserts a copy of an other list at the back of list l.
func (l *List[T]) PushBackList(other *List[T]) {
	if other.Len() == 0 {
		return
	}
	if l.Len() == 0 {
		l.head = other.head
		l.tail = other.tail
		l.len = other.Len()
		return
	}
	l.tail.next = other.head
	other.head.prev = l.tail
	l.tail = other.tail
	l.len += other.Len()
}

// PushFrontList inserts a copy of an other list at the front of list l.
func (l *List[T]) PushFrontList(other *List[T]) {
	if other.Len() == 0 {
		return
	}
	if l.Len() == 0 {
		l.head = other.head
		l.tail = other.tail
		l.len = other.Len()
		return
	}
	other.tail.prev = l.head
	l.head.prev = other.tail
	l.head = other.head
	l.len += other.Len()
}

// MoveAfter moves element e to its new position after element mark.
// If e or mark is nil, or e is not an element of l, or e == mark, no operation is performed.
func (l *List[T]) MoveAfter(e, mark *Element[T]) {
	if e == nil || mark == nil || e == mark || e.list != l {
		return
	}
	l.remove(e)
	l.insert(e, mark.next)
}

// MoveBefore moves element e to its new position before element mark.
// If e or mark is nil, or e is not an element of l, or e == mark, no operation is performed.
func (l *List[T]) MoveBefore(e, mark *Element[T]) {
	if e == nil || mark == nil || e == mark || e.list != l {
		return
	}
	l.remove(e)
	l.insert(e, mark)
}

// insert inserts element e before incoming if incoming is not nil, or at the end of l otherwise.
func (l *List[T]) insert(e, incoming *Element[T]) {
	if incoming == nil {
		l.PushBack(e.Value)
		return
	}
	e.prev = incoming.prev
	e.next = incoming
	if incoming.prev != nil {
		incoming.prev.next = e
	} else {
		l.head = e
	}
	incoming.prev = e
	l.len++
	e.list = l
}

// remove removes e from its list, decrements l.len, and clears e.prev and e.next.
func (l *List[T]) remove(e *Element[T]) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		l.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		l.tail = e.prev
	}
	e.next = nil // avoid memory leaks
	e.prev = nil
	e.list = nil
	l.len--
}

// Transform creates a new list by applying a function to each element of the original list.
func Transform[T any, M any](l *List[T], fn func(T) M) *List[M] {
	newList := New[M]()
	for e := l.Front(); e != nil; e = e.Next() {
		newList.PushBack(fn(e.Value))
	}
	return newList
}
```

**代码逻辑解释（带假设输入与输出）**

我们以 `TestList()` 函数中的一部分为例：

```go
	l2 := a.New[int]()
	e2 := l2.PushFront(2)
	e1 := l2.PushFront(1)
	e3 := l2.PushBack(3)
	e4 := l2.PushBack(600)
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e2, e3, e4})
```

**假设输入:**

* 执行到 `a.New[int]()` 时，创建了一个空的 `int` 类型的链表 `l2`。

**执行过程:**

1. `e2 := l2.PushFront(2)`:  将元素 `2` 添加到 `l2` 的头部。
   * `l2` 的状态变为:  `[2]`， `e2` 指向包含值 `2` 的元素。
2. `e1 := l2.PushFront(1)`:  将元素 `1` 添加到 `l2` 的头部。
   * `l2` 的状态变为:  `[1, 2]`， `e1` 指向包含值 `1` 的元素。
3. `e3 := l2.PushBack(3)`:  将元素 `3` 添加到 `l2` 的尾部。
   * `l2` 的状态变为:  `[1, 2, 3]`， `e3` 指向包含值 `3` 的元素。
4. `e4 := l2.PushBack(600)`: 将元素 `600` 添加到 `l2` 的尾部。
   * `l2` 的状态变为:  `[1, 2, 3, 600]`， `e4` 指向包含值 `600` 的元素。
5. `a.CheckListPointers(l2, []*(a.Element[int]){e1, e2, e3, e4})`:  断言 `l2` 的内部指针是否按照 `e1 -> 2 -> e3 -> e4` 的顺序正确连接。

**假设输出:**

* 如果 `a.CheckListPointers` 没有 panic，则表示链表结构符合预期。

**命令行参数处理**

这段代码本身并没有直接处理命令行参数。它是一个测试文件，通常会通过 `go test` 命令来运行。 `go test` 命令本身有一些参数，例如 `-v` (显示详细输出) 或指定要运行的测试函数等，但这部分逻辑是由 Go 的测试框架处理的，而不是这段代码本身。

**使用者易犯错的点**

1. **操作不属于当前链表的元素:**  `TestIssue4103` 演示了这个问题。 尝试从一个链表中 `Remove` 或 `InsertBefore/After` 不属于该链表的 `Element` 会导致未定义的行为或者 panic（取决于 `a` 包的具体实现）。

   ```go
   func TestIssue4103() {
       l1 := a.New[int]()
       l1.PushBack(1)
       l1.PushBack(2)

       l2 := a.New[int]()
       l2.PushBack(3)
       l2.PushBack(4)

       e := l1.Front() // e 是 l1 的元素
       l2.Remove(e)    // 尝试从 l2 中移除 l1 的元素，这是错误的
       // ...
   }
   ```

2. **在迭代过程中错误地移除元素:**  在 `TestList()` 中展示了正确的迭代移除方式：

   ```go
   // Clear all elements by iterating
   var next *a.Element[int]
   for e := l2.Front(); e != nil; e = next {
       next = e.Next() // 先保存下一个元素
       l2.Remove(e)
   }
   ```
   如果在循环内部直接使用 `e = e.Next()`，那么在 `l2.Remove(e)` 之后，`e` 可能已经失效，导致 `e.Next()` 访问无效内存。

3. **假设移除的元素仍然有效:**  `TestIssue6349` 表明，一旦元素被移除，它就不再是链表的一部分。 尝试访问已移除元素的 `Next()` 或 `Prev()` 可能会导致 `nil` 指针引用。

   ```go
   func TestIssue6349() {
       l := a.New[int]()
       l.PushBack(1)
       l.PushBack(2)

       e := l.Front()
       l.Remove(e)
       if e.Value != 1 { // 仍然可以访问 Value
           panic(fmt.Sprintf("e.value = %d, want 1", e.Value))
       }
       if e.Next() != nil { // 但 Next() 和 Prev() 可能会是 nil
           panic(fmt.Sprintf("e.Next() != nil"))
       }
       if e.Prev() != nil {
           panic(fmt.Sprintf("e.Prev() != nil"))
       }
   }
   ```

4. **使用未初始化的链表:** `TestZeroList()` 验证了即使使用 `var l1 = new(a.List[int])` (只分配了指针，内部字段可能未初始化)，基本操作仍然可以工作。但依赖于未初始化的链表的特定行为可能不是最佳实践。

5. **将非链表元素作为标记 (mark) 传递给 `InsertBefore/After` 或 `MoveBefore/After`:** `TestInsertBeforeUnknownMark`、`TestInsertAfterUnknownMark` 和 `TestMoveUnknownMark` 强调了这一点。 传递一个新创建的 `a.Element[int]` 实例作为 `mark` 是无效的，因为该元素不属于该链表。

希望这个详细的分析对您有所帮助！

### 提示词
```
这是路径为go/test/typeparam/listimp2.dir/main.go的go语言实现的一部分， 请归纳一下它的功能, 　
如果你能推理出它是什么go语言功能的实现，请用go代码举例说明, 
如果介绍代码逻辑，则建议带上假设的输入与输出，
如果涉及命令行参数的具体处理，请详细介绍一下，
如果有哪些使用者易犯错的点，请举例说明，没有则不必说明，
```

### 源代码
```
// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"./a"
	"fmt"
	"strconv"
)

func TestList() {
	l := a.New[string]()
	a.CheckListPointers(l, []*(a.Element[string]){})

	// Single element list
	e := l.PushFront("a")
	a.CheckListPointers(l, []*(a.Element[string]){e})
	l.MoveToFront(e)
	a.CheckListPointers(l, []*(a.Element[string]){e})
	l.MoveToBack(e)
	a.CheckListPointers(l, []*(a.Element[string]){e})
	l.Remove(e)
	a.CheckListPointers(l, []*(a.Element[string]){})

	// Bigger list
	l2 := a.New[int]()
	e2 := l2.PushFront(2)
	e1 := l2.PushFront(1)
	e3 := l2.PushBack(3)
	e4 := l2.PushBack(600)
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e2, e3, e4})

	l2.Remove(e2)
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e3, e4})

	l2.MoveToFront(e3) // move from middle
	a.CheckListPointers(l2, []*(a.Element[int]){e3, e1, e4})

	l2.MoveToFront(e1)
	l2.MoveToBack(e3) // move from middle
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e4, e3})

	l2.MoveToFront(e3) // move from back
	a.CheckListPointers(l2, []*(a.Element[int]){e3, e1, e4})
	l2.MoveToFront(e3) // should be no-op
	a.CheckListPointers(l2, []*(a.Element[int]){e3, e1, e4})

	l2.MoveToBack(e3) // move from front
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e4, e3})
	l2.MoveToBack(e3) // should be no-op
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e4, e3})

	e2 = l2.InsertBefore(2, e1) // insert before front
	a.CheckListPointers(l2, []*(a.Element[int]){e2, e1, e4, e3})
	l2.Remove(e2)
	e2 = l2.InsertBefore(2, e4) // insert before middle
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e2, e4, e3})
	l2.Remove(e2)
	e2 = l2.InsertBefore(2, e3) // insert before back
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e4, e2, e3})
	l2.Remove(e2)

	e2 = l2.InsertAfter(2, e1) // insert after front
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e2, e4, e3})
	l2.Remove(e2)
	e2 = l2.InsertAfter(2, e4) // insert after middle
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e4, e2, e3})
	l2.Remove(e2)
	e2 = l2.InsertAfter(2, e3) // insert after back
	a.CheckListPointers(l2, []*(a.Element[int]){e1, e4, e3, e2})
	l2.Remove(e2)

	// Check standard iteration.
	sum := 0
	for e := l2.Front(); e != nil; e = e.Next() {
		sum += e.Value
	}
	if sum != 604 {
		panic(fmt.Sprintf("sum over l = %d, want 604", sum))
	}

	// Clear all elements by iterating
	var next *a.Element[int]
	for e := l2.Front(); e != nil; e = next {
		next = e.Next()
		l2.Remove(e)
	}
	a.CheckListPointers(l2, []*(a.Element[int]){})
}

func checkList[T comparable](l *a.List[T], es []interface{}) {
	if !a.CheckListLen(l, len(es)) {
		return
	}

	i := 0
	for e := l.Front(); e != nil; e = e.Next() {
		le := e.Value
		// Comparison between a generically-typed variable le and an interface.
		if le != es[i] {
			panic(fmt.Sprintf("elt[%d].Value = %v, want %v", i, le, es[i]))
		}
		i++
	}
}

func TestExtending() {
	l1 := a.New[int]()
	l2 := a.New[int]()

	l1.PushBack(1)
	l1.PushBack(2)
	l1.PushBack(3)

	l2.PushBack(4)
	l2.PushBack(5)

	l3 := a.New[int]()
	l3.PushBackList(l1)
	checkList(l3, []interface{}{1, 2, 3})
	l3.PushBackList(l2)
	checkList(l3, []interface{}{1, 2, 3, 4, 5})

	l3 = a.New[int]()
	l3.PushFrontList(l2)
	checkList(l3, []interface{}{4, 5})
	l3.PushFrontList(l1)
	checkList(l3, []interface{}{1, 2, 3, 4, 5})

	checkList(l1, []interface{}{1, 2, 3})
	checkList(l2, []interface{}{4, 5})

	l3 = a.New[int]()
	l3.PushBackList(l1)
	checkList(l3, []interface{}{1, 2, 3})
	l3.PushBackList(l3)
	checkList(l3, []interface{}{1, 2, 3, 1, 2, 3})

	l3 = a.New[int]()
	l3.PushFrontList(l1)
	checkList(l3, []interface{}{1, 2, 3})
	l3.PushFrontList(l3)
	checkList(l3, []interface{}{1, 2, 3, 1, 2, 3})

	l3 = a.New[int]()
	l1.PushBackList(l3)
	checkList(l1, []interface{}{1, 2, 3})
	l1.PushFrontList(l3)
	checkList(l1, []interface{}{1, 2, 3})
}

func TestRemove() {
	l := a.New[int]()
	e1 := l.PushBack(1)
	e2 := l.PushBack(2)
	a.CheckListPointers(l, []*(a.Element[int]){e1, e2})
	e := l.Front()
	l.Remove(e)
	a.CheckListPointers(l, []*(a.Element[int]){e2})
	l.Remove(e)
	a.CheckListPointers(l, []*(a.Element[int]){e2})
}

func TestIssue4103() {
	l1 := a.New[int]()
	l1.PushBack(1)
	l1.PushBack(2)

	l2 := a.New[int]()
	l2.PushBack(3)
	l2.PushBack(4)

	e := l1.Front()
	l2.Remove(e) // l2 should not change because e is not an element of l2
	if n := l2.Len(); n != 2 {
		panic(fmt.Sprintf("l2.Len() = %d, want 2", n))
	}

	l1.InsertBefore(8, e)
	if n := l1.Len(); n != 3 {
		panic(fmt.Sprintf("l1.Len() = %d, want 3", n))
	}
}

func TestIssue6349() {
	l := a.New[int]()
	l.PushBack(1)
	l.PushBack(2)

	e := l.Front()
	l.Remove(e)
	if e.Value != 1 {
		panic(fmt.Sprintf("e.value = %d, want 1", e.Value))
	}
	if e.Next() != nil {
		panic(fmt.Sprintf("e.Next() != nil"))
	}
	if e.Prev() != nil {
		panic(fmt.Sprintf("e.Prev() != nil"))
	}
}

func TestMove() {
	l := a.New[int]()
	e1 := l.PushBack(1)
	e2 := l.PushBack(2)
	e3 := l.PushBack(3)
	e4 := l.PushBack(4)

	l.MoveAfter(e3, e3)
	a.CheckListPointers(l, []*(a.Element[int]){e1, e2, e3, e4})
	l.MoveBefore(e2, e2)
	a.CheckListPointers(l, []*(a.Element[int]){e1, e2, e3, e4})

	l.MoveAfter(e3, e2)
	a.CheckListPointers(l, []*(a.Element[int]){e1, e2, e3, e4})
	l.MoveBefore(e2, e3)
	a.CheckListPointers(l, []*(a.Element[int]){e1, e2, e3, e4})

	l.MoveBefore(e2, e4)
	a.CheckListPointers(l, []*(a.Element[int]){e1, e3, e2, e4})
	e2, e3 = e3, e2

	l.MoveBefore(e4, e1)
	a.CheckListPointers(l, []*(a.Element[int]){e4, e1, e2, e3})
	e1, e2, e3, e4 = e4, e1, e2, e3

	l.MoveAfter(e4, e1)
	a.CheckListPointers(l, []*(a.Element[int]){e1, e4, e2, e3})
	e2, e3, e4 = e4, e2, e3

	l.MoveAfter(e2, e3)
	a.CheckListPointers(l, []*(a.Element[int]){e1, e3, e2, e4})
	e2, e3 = e3, e2
}

// Test PushFront, PushBack, PushFrontList, PushBackList with uninitialized a.List
func TestZeroList() {
	var l1 = new(a.List[int])
	l1.PushFront(1)
	checkList(l1, []interface{}{1})

	var l2 = new(a.List[int])
	l2.PushBack(1)
	checkList(l2, []interface{}{1})

	var l3 = new(a.List[int])
	l3.PushFrontList(l1)
	checkList(l3, []interface{}{1})

	var l4 = new(a.List[int])
	l4.PushBackList(l2)
	checkList(l4, []interface{}{1})
}

// Test that a list l is not modified when calling InsertBefore with a mark that is not an element of l.
func TestInsertBeforeUnknownMark() {
	var l a.List[int]
	l.PushBack(1)
	l.PushBack(2)
	l.PushBack(3)
	l.InsertBefore(1, new(a.Element[int]))
	checkList(&l, []interface{}{1, 2, 3})
}

// Test that a list l is not modified when calling InsertAfter with a mark that is not an element of l.
func TestInsertAfterUnknownMark() {
	var l a.List[int]
	l.PushBack(1)
	l.PushBack(2)
	l.PushBack(3)
	l.InsertAfter(1, new(a.Element[int]))
	checkList(&l, []interface{}{1, 2, 3})
}

// Test that a list l is not modified when calling MoveAfter or MoveBefore with a mark that is not an element of l.
func TestMoveUnknownMark() {
	var l1 a.List[int]
	e1 := l1.PushBack(1)

	var l2 a.List[int]
	e2 := l2.PushBack(2)

	l1.MoveAfter(e1, e2)
	checkList(&l1, []interface{}{1})
	checkList(&l2, []interface{}{2})

	l1.MoveBefore(e1, e2)
	checkList(&l1, []interface{}{1})
	checkList(&l2, []interface{}{2})
}

// Test the Transform function.
func TestTransform() {
	l1 := a.New[int]()
	l1.PushBack(1)
	l1.PushBack(2)
	l2 := a.Transform(l1, strconv.Itoa)
	checkList(l2, []interface{}{"1", "2"})
}

func main() {
	TestList()
	TestExtending()
	TestRemove()
	TestIssue4103()
	TestIssue6349()
	TestMove()
	TestZeroList()
	TestInsertBeforeUnknownMark()
	TestInsertAfterUnknownMark()
	TestTransform()
}
```